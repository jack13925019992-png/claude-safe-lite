//! 安全模式后台巡检与泄露自动熔断状态机（Watchdog / Kill Switch）
//!
//! 严格遵循需求文档 3.3 & 5.1：
//! 1. 双引擎实时监测：30/45/60s 后台定时巡检 + Forwarder 连续上游失败即时唤醒；
//! 2. 防误报策略：
//!    - 明确检测到出口 IP 偏离基线或 DNS 走本地泄露 → 0 延迟立即触发熔断；
//!    - 网络超时或代理不可达 → 3 秒内自动复测 1 次，连续 2 次确认掉线后立即触发熔断；
//! 3. 严格原子熔断链：
//!    ① `Forwarder.trip()` 毫秒级断流 → ② `BrowserLauncher.force_kill()` 强杀进程树 →
//!    ③ 推送 Windows 原生告警通知与 `watchdog-alert` → ④ 进入 `Tripped` 锁定态并写入双日志；
//! 4. 解锁闭环：锁定态下禁止启动（含禁止强制启动绕过），必须手动重新检测且关键项全绿无泄露方可解锁。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Local;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::browser_launcher::BrowserLauncher;
use crate::checker::{CheckReport, Checker, WatchdogProbeOutcome};
use crate::constants::WATCHDOG_RETRY_DELAY_SECS;
use crate::forwarder::ForwarderManager;
use crate::human_errors::HumanizedError;
use crate::logger::{LogKind, Logger};

/// 熔断触发分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripKind {
    IpOrDnsLeak,
    ProxyDisconnected,
}

/// 推送给前端的熔断器与巡检状态快照（严格对齐需求文档 8.3 `circuit-breaker-state`）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerSnapshot {
    pub locked: bool,
    pub reason: Option<String>,
    pub trip_kind: Option<TripKind>,
    pub triggered_at: Option<String>,
    pub last_check_at: Option<String>,
    pub monitoring_active: bool,
}

/// 熔断触发时的结构化告警载荷（对齐需求文档 8.3 `watchdog-alert` 及 5.1 原生通知文案）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchdogAlertPayload {
    pub trip_kind: TripKind,
    pub notification_title: String,
    /// Windows 原生系统托盘通知正文（严格采用文档 5.1 指定文案）
    pub notification_body: String,
    /// 主界面红色横幅详情（人话原因 + 建议动作 + 脱敏技术细节）
    pub banner_error: HumanizedError,
    pub triggered_at: String,
}

struct WatchdogInternalState {
    locked: bool,
    reason: Option<String>,
    trip_kind: Option<TripKind>,
    triggered_at: Option<String>,
    last_check_at: Option<String>,
    active_monitor_cancel: Option<CancellationToken>,
}

pub struct Watchdog {
    forwarder_mgr: Arc<ForwarderManager>,
    browser_launcher: Arc<BrowserLauncher>,
    checker: Arc<Checker>,
    logger: Arc<Logger>,
    retry_delay: Duration,
    state: Mutex<WatchdogInternalState>,
    state_listener: Mutex<Option<Arc<dyn Fn(CircuitBreakerSnapshot) + Send + Sync>>>,
    alert_listener: Mutex<Option<Arc<dyn Fn(WatchdogAlertPayload) + Send + Sync>>>,
    warning_listener: Mutex<Option<Arc<dyn Fn(String, String) + Send + Sync>>>,
}

impl Watchdog {
    pub fn new(
        forwarder_mgr: Arc<ForwarderManager>,
        browser_launcher: Arc<BrowserLauncher>,
        checker: Arc<Checker>,
        logger: Arc<Logger>,
    ) -> Arc<Self> {
        Self::with_retry_delay(
            forwarder_mgr,
            browser_launcher,
            checker,
            logger,
            Duration::from_secs(WATCHDOG_RETRY_DELAY_SECS),
        )
    }

    pub fn with_retry_delay(
        forwarder_mgr: Arc<ForwarderManager>,
        browser_launcher: Arc<BrowserLauncher>,
        checker: Arc<Checker>,
        logger: Arc<Logger>,
        retry_delay: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            forwarder_mgr,
            browser_launcher,
            checker,
            logger,
            retry_delay,
            state: Mutex::new(WatchdogInternalState {
                locked: false,
                reason: None,
                trip_kind: None,
                triggered_at: None,
                last_check_at: None,
                active_monitor_cancel: None,
            }),
            state_listener: Mutex::new(None),
            alert_listener: Mutex::new(None),
            warning_listener: Mutex::new(None),
        })
    }

    pub fn set_state_listener<F>(&self, cb: F)
    where
        F: Fn(CircuitBreakerSnapshot) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.state_listener.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    pub fn set_alert_listener<F>(&self, cb: F)
    where
        F: Fn(WatchdogAlertPayload) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.alert_listener.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    pub fn set_warning_listener<F>(&self, cb: F)
    where
        F: Fn(String, String) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.warning_listener.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    pub fn snapshot(&self) -> CircuitBreakerSnapshot {
        let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        CircuitBreakerSnapshot {
            locked: g.locked,
            reason: g.reason.clone(),
            trip_kind: g.trip_kind,
            triggered_at: g.triggered_at.clone(),
            last_check_at: g.last_check_at.clone(),
            monitoring_active: g.active_monitor_cancel.is_some(),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).locked
    }

    fn emit_snapshot(&self) {
        let snap = self.snapshot();
        let cb = self
            .state_listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(f) = cb {
            f(snap);
        }
    }

    /// 在安全浏览器运行期间启动双引擎后台保护巡检
    pub fn start_monitoring(
        self: &Arc<Self>,
        forwarder_port: u16,
        baseline_ip: String,
        baseline_country: Option<String>,
        interval: Duration,
    ) {
        let cancel_token = CancellationToken::new();
        {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(old) = g.active_monitor_cancel.replace(cancel_token.clone()) {
                old.cancel();
            }
            g.last_check_at = Some(Local::now().format("%H:%M:%S").to_string());
        }
        self.emit_snapshot();

        self.logger.info(
            LogKind::Check,
            format!(
                "安全模式后台巡检已启动: 基线出口IP={}, 巡检周期={}s, 本地转发端口=127.0.0.1:{}",
                baseline_ip,
                interval.as_secs(),
                forwarder_port
            ),
        );

        let wd = self.clone();
        let suspect_notify = self.forwarder_mgr.upstream_suspect_notifier();

        tokio::spawn(async move {
            let mut claude_warned = false;
            loop {
                let woke_by_suspect = tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    _ = suspect_notify.notified() => {
                        true
                    }
                    _ = tokio::time::sleep(interval) => {
                        false
                    }
                };

                if cancel_token.is_cancelled() {
                    break;
                }

                if woke_by_suspect {
                    wd.logger.warn(
                        LogKind::Check,
                        "收到 Forwarder 连续上游握手失败信号，立即执行快速巡检探测",
                    );
                }

                let first_outcome = wd
                    .checker
                    .run_watchdog_probe(forwarder_port, &baseline_ip, baseline_country.as_deref())
                    .await;

                if cancel_token.is_cancelled() {
                    break;
                }

                match first_outcome {
                    WatchdogProbeOutcome::Healthy { current_ip } => {
                        claude_warned = false;
                        wd.mark_check_healthy(&current_ip);
                    }
                    WatchdogProbeOutcome::ExplicitLeak { detail, .. } => {
                        // 明确检测到 IP 偏离基线或 DNS 泄露：零容忍、0 延迟立即熔断！
                        wd.execute_atomic_trip(TripKind::IpOrDnsLeak, &detail);
                        break;
                    }
                    WatchdogProbeOutcome::ClaudeUnreachable { detail: first_err } => {
                        wd.logger.warn(
                            LogKind::Check,
                            format!(
                                "安全巡检首次探测到 Claude 访问异常 ({})，将在 {:?} 后复测确认",
                                first_err, wd.retry_delay
                            ),
                        );

                        tokio::select! {
                            biased;
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(wd.retry_delay) => {}
                        }

                        if cancel_token.is_cancelled() {
                            break;
                        }

                        let second_outcome = wd
                            .checker
                            .run_watchdog_probe(
                                forwarder_port,
                                &baseline_ip,
                                baseline_country.as_deref(),
                            )
                            .await;

                        if cancel_token.is_cancelled() {
                            break;
                        }

                        match second_outcome {
                            WatchdogProbeOutcome::Healthy { current_ip } => {
                                claude_warned = false;
                                wd.mark_check_healthy(&current_ip);
                            }
                            WatchdogProbeOutcome::ExplicitLeak { detail, .. } => {
                                wd.execute_atomic_trip(TripKind::IpOrDnsLeak, &detail);
                                break;
                            }
                            WatchdogProbeOutcome::TransientOrDisconnected { detail: second_err } => {
                                let combined = format!(
                                    "巡检复测确认代理连接已断开 (首次: {}; 复测: {})",
                                    first_err, second_err
                                );
                                wd.execute_atomic_trip(TripKind::ProxyDisconnected, &combined);
                                break;
                            }
                            WatchdogProbeOutcome::ClaudeUnreachable { detail: second_err } => {
                                wd.logger.warn(
                                    LogKind::Check,
                                    format!(
                                        "安全巡检连续 2 次确认 Claude 不可访问 ({})",
                                        second_err
                                    ),
                                );
                                if !claude_warned {
                                    claude_warned = true;
                                    let warn_cb = wd
                                        .warning_listener
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .clone();
                                    if let Some(cb) = warn_cb {
                                        cb(
                                            "Claude安全客户端 · 巡检异常提醒".to_string(),
                                            format!(
                                                "后台安全巡检检测到 Claude 当前不可访问（{}），请检查代理节点状态或切换节点。",
                                                wd.logger.sanitize(&second_err)
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    WatchdogProbeOutcome::TransientOrDisconnected { detail: first_err } => {
                        // 防瞬时网络抖动：3 秒内自动复测 1 次
                        wd.logger.warn(
                            LogKind::Check,
                            format!(
                                "安全巡检首次探测异常 ({})，将在 {:?} 后执行二次确认复测",
                                first_err, wd.retry_delay
                            ),
                        );

                        tokio::select! {
                            biased;
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(wd.retry_delay) => {}
                        }

                        if cancel_token.is_cancelled() {
                            break;
                        }

                        let second_outcome = wd
                            .checker
                            .run_watchdog_probe(
                                forwarder_port,
                                &baseline_ip,
                                baseline_country.as_deref(),
                            )
                            .await;

                        if cancel_token.is_cancelled() {
                            break;
                        }

                        match second_outcome {
                            WatchdogProbeOutcome::Healthy { current_ip } => {
                                claude_warned = false;
                                wd.logger.info(
                                    LogKind::Check,
                                    format!(
                                        "二次复测已恢复正常 (出口IP={})，判定为瞬时网络抖动，继续运行",
                                        current_ip
                                    ),
                                );
                                wd.mark_check_healthy(&current_ip);
                            }
                            WatchdogProbeOutcome::ExplicitLeak { detail, .. } => {
                                wd.execute_atomic_trip(TripKind::IpOrDnsLeak, &detail);
                                break;
                            }
                            WatchdogProbeOutcome::ClaudeUnreachable { detail: second_err } => {
                                if !claude_warned {
                                    claude_warned = true;
                                    let warn_cb = wd
                                        .warning_listener
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .clone();
                                    if let Some(cb) = warn_cb {
                                        cb(
                                            "Claude安全客户端 · 巡检异常提醒".to_string(),
                                            format!(
                                                "后台安全巡检检测到 Claude 当前不可访问（{}），请检查代理节点状态或切换节点。",
                                                wd.logger.sanitize(&second_err)
                                            ),
                                        );
                                    }
                                }
                            }
                            WatchdogProbeOutcome::TransientOrDisconnected { detail: second_err } => {
                                let combined = format!(
                                    "连续 2 次探测确认代理掉线 (首次: {}; 复测: {})",
                                    first_err, second_err
                                );
                                wd.execute_atomic_trip(TripKind::ProxyDisconnected, &combined);
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    fn mark_check_healthy(&self, current_ip: &str) {
        let now_str = Local::now().format("%H:%M:%S").to_string();
        {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.last_check_at = Some(now_str);
        }
        self.logger.info(
            LogKind::Check,
            format!("安全模式后台巡检通过 (当前出口 IP: {})", current_ip),
        );
        self.emit_snapshot();
    }

    /// 停止后台巡检（例如用户正常关闭安全浏览器，或用户在主界面主动关闭了安全模式开关）
    pub fn stop_monitoring(&self) {
        let had_token = {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.active_monitor_cancel.take()
        };
        if let Some(tok) = had_token {
            tok.cancel();
            self.logger.info(LogKind::Check, "安全模式后台巡检已停止");
            self.emit_snapshot();
        }
    }

    /// 熔断自动执行链（严格按需求文档 5.1 第 196~203 行顺序原子执行）
    pub fn execute_atomic_trip(&self, kind: TripKind, raw_detail: &str) {
        let sanitized_detail = self.logger.sanitize(raw_detail);
        let triggered_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let (notification_body, banner_error) = match kind {
            TripKind::IpOrDnsLeak => (
                "检测到 IP/DNS 泄露，已强制关闭安全浏览器".to_string(),
                HumanizedError::leak_circuit_tripped(&sanitized_detail, Some(&self.logger)),
            ),
            TripKind::ProxyDisconnected => (
                "代理连接已断开，为防止泄露已强制关闭安全浏览器".to_string(),
                HumanizedError::disconnect_circuit_tripped(&sanitized_detail, Some(&self.logger)),
            ),
        };

        // 1. 第一步：立即暂停本地转发器（毫秒级切断全部现有与新建连接）
        self.forwarder_mgr.trip(&notification_body);

        // 2. 第二步：通过 Win32 Job Object 强制终止安全浏览器整个进程树
        self.browser_launcher.force_kill(&notification_body);

        // 3. 切换状态为 Tripped 锁定态并取消旧巡检循环
        {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(tok) = g.active_monitor_cancel.take() {
                tok.cancel();
            }
            g.locked = true;
            g.reason = Some(banner_error.user_message.clone());
            g.trip_kind = Some(kind);
            g.triggered_at = Some(triggered_at.clone());
        }

        // 4. 将熔断原因、时间戳与脱敏详情同时写入 launch.log 与 app.log
        let log_entry = format!(
            "【安全熔断触发】类型={:?} | 提示={} | 详情={}",
            kind, notification_body, sanitized_detail
        );
        self.logger.error(LogKind::Launch, &log_entry);
        self.logger.error(LogKind::App, &log_entry);

        // 5. 推送系统托盘原生通知、前端 watchdog-alert 与 circuit-breaker-state 锁定横幅
        self.emit_snapshot();

        let alert_cb = self
            .alert_listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(cb) = alert_cb {
            cb(WatchdogAlertPayload {
                trip_kind: kind,
                notification_title: "Claude Safe Lite 安全熔断告警".to_string(),
                notification_body,
                banner_error,
                triggered_at,
            });
        }
    }

    /// 当用户手动点击「重新检测」完成后调用：若关键项（01、02、04）全部通过且无泄露，自动解除锁定
    pub fn try_unlock_after_recheck(&self, report: &CheckReport) -> bool {
        if !self.is_locked() {
            return false;
        }
        if !report.can_unlock_circuit_breaker() {
            return false;
        }

        {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.locked = false;
            g.reason = None;
            g.trip_kind = None;
            g.triggered_at = None;
            g.last_check_at = Some(Local::now().format("%H:%M:%S").to_string());
        }

        self.forwarder_mgr.clear_trip_lock();
        self.logger.info(
            LogKind::App,
            "重新检测关键项全部通过且无泄露，已自动解除安全熔断锁定状态",
        );
        self.emit_snapshot();
        true
    }
}
