//! 五项检测引擎与防抖调度模块（Checker）
//!
//! 核心原则（需求文档 4.3 & 4.4）：
//! 1. 所有检测流量 100% 强制经由本地 `Forwarder`（`socks5h://127.0.0.1:<port>`）发出，确保域名透传零本地解析；
//! 2. 单项超时 10 秒；01「代理连接」失败时，02–05 立即置为 `pending`（待定/灰）；
//! 3. 支持 `CancellationToken` 防抖取消：新检测触发时立即取消正在进行的旧任务；
//! 4. 检测端点集中在 `CheckEndpointsConfig`（默认读取 `constants.rs`），既方便日后替换又支持离线 Mock 全链路测试。

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Local;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::constants::{
    CLAUDE_WEB_URL, DNS_LEAK_EDNS_DOMAIN_SUFFIX, FAST_IP_TRACE_ENDPOINTS, GEO_IP_ENDPOINTS,
    IP_RISK_FALLBACK_TEMPLATE, IP_RISK_PRIMARY_TEMPLATE, IP_RISK_WARN_THRESHOLD,
    LOCAL_ISP_DNS_COUNTRY_CODES, PROBE_TARGET_HOST, PROBE_TARGET_PORT, SINGLE_CHECK_TIMEOUT_SECS,
    UNSUPPORTED_COUNTRY_CODES,
};
use crate::forwarder::{ForwarderManager, LeaseOwner, RunningForwarderCore};
use crate::human_errors::HumanizedError;
use crate::logger::{LogKind, Logger};
use crate::proxy_store::ResolvedUpstreamProxy;
use crate::socks5::{
    build_socks5_connect_request, TargetAddr, UpstreamError, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    AUTH_METHOD_NONE, REP_SUCCEEDED, SOCKS5_VERSION,
};

#[cfg(target_os = "macos")]
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

#[cfg(not(target_os = "macos"))]
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// 五盏灯状态定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LightStatus {
    Green,
    Yellow,
    Red,
    Pending,
    Checking,
}

/// 单项检测标识
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    ProxyConnection,
    ExitIpCountry,
    IpRiskScore,
    ClaudeAccess,
    DnsLeak,
}

/// 单盏灯结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckItemResult {
    pub index: u8,
    pub id: CheckId,
    pub title: String,
    /// 是否为关键阻断项（01、02、04 为 true；03、05 为 false）
    pub critical: bool,
    pub status: LightStatus,
    /// 卡片副标题/简短结论
    pub summary: String,
    /// 失败或警告时的友好报错详情（人话原因 + 建议动作 + 折叠脱敏技术细节）
    pub error: Option<HumanizedError>,
    pub latency_ms: Option<u64>,
}

/// 完整五项检测报告（同时作为 `check-progress` 事件载荷推送给前端）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckReport {
    pub proxy_id: String,
    pub proxy_name: String,
    pub is_running: bool,
    pub completed_at: Option<String>,
    pub exit_ip: Option<String>,
    pub country_code: Option<String>,
    pub country_display: Option<String>,
    pub isp: Option<String>,
    pub risk_score: Option<u32>,
    pub items: Vec<CheckItemResult>,
}

impl CheckReport {
    pub fn initial(proxy_id: &str, proxy_name: &str, checking_first: bool) -> Self {
        let first_status = if checking_first {
            LightStatus::Checking
        } else {
            LightStatus::Pending
        };
        let first_summary = if checking_first {
            "正在握手检测...".to_string()
        } else {
            "待检测".to_string()
        };

        Self {
            proxy_id: proxy_id.to_string(),
            proxy_name: proxy_name.to_string(),
            is_running: checking_first,
            completed_at: None,
            exit_ip: None,
            country_code: None,
            country_display: None,
            isp: None,
            risk_score: None,
            items: vec![
                CheckItemResult {
                    index: 1,
                    id: CheckId::ProxyConnection,
                    title: "代理连接".to_string(),
                    critical: true,
                    status: first_status,
                    summary: first_summary,
                    error: None,
                    latency_ms: None,
                },
                CheckItemResult {
                    index: 2,
                    id: CheckId::ExitIpCountry,
                    title: "出口IP国家".to_string(),
                    critical: true,
                    status: LightStatus::Pending,
                    summary: "待定".to_string(),
                    error: None,
                    latency_ms: None,
                },
                CheckItemResult {
                    index: 3,
                    id: CheckId::IpRiskScore,
                    title: "IP风险评分".to_string(),
                    critical: false,
                    status: LightStatus::Pending,
                    summary: "待定".to_string(),
                    error: None,
                    latency_ms: None,
                },
                CheckItemResult {
                    index: 4,
                    id: CheckId::ClaudeAccess,
                    title: "Claude可访问".to_string(),
                    critical: true,
                    status: LightStatus::Pending,
                    summary: "待定".to_string(),
                    error: None,
                    latency_ms: None,
                },
                CheckItemResult {
                    index: 5,
                    id: CheckId::DnsLeak,
                    title: "DNS泄露".to_string(),
                    critical: false,
                    status: LightStatus::Pending,
                    summary: "待定".to_string(),
                    error: None,
                    latency_ms: None,
                },
            ],
        }
    }

    /// 关键项（01 代理连接、02 出口IP国家、04 Claude可访问）是否全部绿灯
    pub fn critical_all_green(&self) -> bool {
        self.items
            .iter()
            .filter(|i| i.critical)
            .all(|i| i.status == LightStatus::Green)
    }

    /// 非关键项（03 IP风险评分、05 DNS泄露）是否存在黄灯或红灯警告
    pub fn non_critical_warnings(&self) -> Vec<&CheckItemResult> {
        self.items
            .iter()
            .filter(|i| !i.critical && matches!(i.status, LightStatus::Yellow | LightStatus::Red))
            .collect()
    }

    /// 是否满足解除安全熔断锁定的条件：关键项全绿且无明确 DNS 泄露（05 非红灯）
    pub fn can_unlock_circuit_breaker(&self) -> bool {
        let no_dns_leak = self
            .items
            .iter()
            .find(|i| i.id == CheckId::DnsLeak)
            .map(|i| i.status != LightStatus::Red)
            .unwrap_or(false);
        self.critical_all_green() && no_dns_leak
    }
}

/// 可注入的检测端点配置（默认使用 `constants.rs` 公共免 Key 接口）
#[derive(Debug, Clone)]
pub struct CheckEndpointsConfig {
    pub item_timeout: Duration,
    pub probe_host: String,
    pub probe_port: u16,
    pub geo_ip_urls: Vec<String>,
    pub fast_ip_urls: Vec<String>,
    pub ip_risk_primary_template: String,
    pub ip_risk_fallback_template: String,
    pub claude_url: String,
    /// 若为 `None`，默认请求 `https://{rand}.edns.ip-api.com/json`；测试时可指定本地 URL 模板
    pub dns_leak_url_override: Option<String>,
}

impl Default for CheckEndpointsConfig {
    fn default() -> Self {
        Self {
            item_timeout: Duration::from_secs(SINGLE_CHECK_TIMEOUT_SECS),
            probe_host: PROBE_TARGET_HOST.to_string(),
            probe_port: PROBE_TARGET_PORT,
            geo_ip_urls: GEO_IP_ENDPOINTS.iter().map(|s| (*s).to_string()).collect(),
            fast_ip_urls: FAST_IP_TRACE_ENDPOINTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            ip_risk_primary_template: IP_RISK_PRIMARY_TEMPLATE.to_string(),
            ip_risk_fallback_template: IP_RISK_FALLBACK_TEMPLATE.to_string(),
            claude_url: CLAUDE_WEB_URL.to_string(),
            dns_leak_url_override: None,
        }
    }
}

/// Watchdog 后台快速巡检单次结果
#[derive(Debug, Clone)]
pub enum WatchdogProbeOutcome {
    /// 出口 IP、DNS 与 Claude 可访问性均正常
    Healthy { current_ip: String },
    /// 明确检测到泄露（出口 IP 偏离代理基线 / DNS 落入本地直连）—— 须 0 延迟立即熔断！
    ExplicitLeak { reason: String, detail: String },
    /// 网络超时或上游代理连接断开 —— 须 3 秒内复测 1 次防误报，连续 2 次确认后熔断并发送系统通知
    TransientOrDisconnected { detail: String },
    /// 代理连通且无泄露，但检测到 Claude 站点不可访问（如 403/429 或目标超时）—— 复测确认后发送系统通知提醒用户
    ClaudeUnreachable { detail: String },
}

/// 五项检测协调器（管理防抖取消与最近一次报告缓存）
pub struct Checker {
    forwarder_mgr: Arc<ForwarderManager>,
    logger: Arc<Logger>,
    endpoints: CheckEndpointsConfig,
    active_cancel: Mutex<Option<CancellationToken>>,
    latest_report: Mutex<Option<CheckReport>>,
}

impl Checker {
    pub fn new(forwarder_mgr: Arc<ForwarderManager>, logger: Arc<Logger>) -> Arc<Self> {
        Self::with_endpoints(forwarder_mgr, logger, CheckEndpointsConfig::default())
    }

    pub fn with_endpoints(
        forwarder_mgr: Arc<ForwarderManager>,
        logger: Arc<Logger>,
        endpoints: CheckEndpointsConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            forwarder_mgr,
            logger,
            endpoints,
            active_cancel: Mutex::new(None),
            latest_report: Mutex::new(None),
        })
    }

    pub fn endpoints(&self) -> &CheckEndpointsConfig {
        &self.endpoints
    }

    pub fn latest_report(&self) -> Option<CheckReport> {
        self.latest_report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// 立即取消正在进行的五项检测任务（防抖或手动取消）
    pub fn cancel_current(&self) {
        if let Ok(mut guard) = self.active_cancel.lock() {
            if let Some(prev) = guard.take() {
                prev.cancel();
            }
        }
    }

    /// 表单内点击「测试连接」：仅单独执行第 01 项检测（走独立临时 Forwarder，不干扰主状态）
    pub async fn test_single_connection(
        &self,
        upstream: ResolvedUpstreamProxy,
    ) -> Result<CheckItemResult, HumanizedError> {
        let ephemeral = self.forwarder_mgr.spawn_ephemeral(upstream).await?;
        let item = run_step_01_connection(
            ephemeral.core(),
            &self.endpoints.probe_host,
            self.endpoints.probe_port,
            self.endpoints.item_timeout,
            &self.logger,
        )
        .await;
        ephemeral.shutdown().await;
        Ok(item)
    }

    /// 执行完整五项检测（若已有旧检测在跑，先通过 `CancellationToken` 自动取消旧任务）
    pub async fn run_all_checks<F>(
        &self,
        upstream: ResolvedUpstreamProxy,
        on_progress: F,
    ) -> Result<CheckReport, HumanizedError>
    where
        F: Fn(&CheckReport) + Send + Sync,
    {
        // 防抖：取消上一轮未完成的检测任务
        let cancel_token = CancellationToken::new();
        {
            let mut guard = self
                .active_cancel
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(old) = guard.replace(cancel_token.clone()) {
                old.cancel();
            }
        }

        let proxy_id = upstream.id.clone();
        let proxy_name = upstream.name.clone();
        self.logger.info(
            LogKind::Check,
            format!("开始执行五项安全检测 (代理配置: {})", proxy_name),
        );

        let mut report = CheckReport::initial(&proxy_id, &proxy_name, true);
        on_progress(&report);

        // 若主转发器未锁定且空闲/同配置，则租用共享转发器；若处于熔断态或被其他配置占用，则使用隔离临时转发器执行重检
        enum ForwarderHolder {
            Shared(crate::forwarder::ForwarderLease),
            Temp(crate::forwarder::EphemeralForwarder),
        }

        let holder = if self.forwarder_mgr.is_tripped() {
            ForwarderHolder::Temp(self.forwarder_mgr.spawn_ephemeral(upstream).await?)
        } else {
            match self
                .forwarder_mgr
                .acquire_lease(upstream.clone(), LeaseOwner::CheckOrWatchdog)
                .await
            {
                Ok(lease) => ForwarderHolder::Shared(lease),
                Err(_) => ForwarderHolder::Temp(self.forwarder_mgr.spawn_ephemeral(upstream).await?),
            }
        };

        let core: Arc<RunningForwarderCore> = match &holder {
            ForwarderHolder::Shared(l) => l.core().clone(),
            ForwarderHolder::Temp(e) => e.core().clone(),
        };

        // ---- 第 01 项：代理连接 ----
        let item01 = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => {
                return Err(Self::cancelled_err());
            }
            res = run_step_01_connection(
                &core,
                &self.endpoints.probe_host,
                self.endpoints.probe_port,
                self.endpoints.item_timeout,
                &self.logger,
            ) => res,
        };

        report.items[0] = item01;

        // 联动铁律：01 失败时，02–05 立即置为待定（Pending/灰）并终止后续检测
        if report.items[0].status != LightStatus::Green {
            for item in report.items.iter_mut().skip(1) {
                item.status = LightStatus::Pending;
                item.summary = "待定（需先通过代理连接）".to_string();
                item.error = None;
            }
            report.is_running = false;
            report.completed_at = Some(Local::now().format("%H:%M:%S").to_string());
            self.save_and_emit(&report, &on_progress);
            self.logger.warn(
                LogKind::Check,
                format!(
                    "[01 代理连接] 失败: {}，其余四项置为待定",
                    report.items[0].summary
                ),
            );
            if let ForwarderHolder::Temp(ephemeral) = holder {
                ephemeral.shutdown().await;
            }
            return Ok(report);
        }

        // 构建强制走本地 Forwarder (socks5h://127.0.0.1:<port>) 的 HTTP 客户端
        let forwarder_port = core.port();
        let http_client = build_proxied_http_client(forwarder_port, self.endpoints.item_timeout, true)?;
        let no_redirect_client =
            build_proxied_http_client(forwarder_port, self.endpoints.item_timeout, false)?;

        // ---- 第 02 项：出口 IP 国家 ----
        report.items[1].status = LightStatus::Checking;
        report.items[1].summary = "正在查询出口 IP 与归属地...".to_string();
        on_progress(&report);

        let geo_outcome = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Err(Self::cancelled_err()),
            res = run_step_02_geo_ip(&http_client, &self.endpoints, &self.logger) => res,
        };

        report.items[1] = geo_outcome.item;
        report.exit_ip = geo_outcome.exit_ip.clone();
        report.country_code = geo_outcome.country_code.clone();
        report.country_display = geo_outcome.country_display.clone();
        report.isp = geo_outcome.isp.clone();
        on_progress(&report);

        // ---- 第 03 项：IP 风险评分 ----
        report.items[2].status = LightStatus::Checking;
        report.items[2].summary = "正在评估 IP 纯净度与风控等级...".to_string();
        on_progress(&report);

        let (item03, score_opt) = if let Some(ref ip) = report.exit_ip {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => return Err(Self::cancelled_err()),
                res = run_step_03_ip_risk(&http_client, ip, &self.endpoints, &self.logger) => res,
            }
        } else {
            (
                CheckItemResult {
                    index: 3,
                    id: CheckId::IpRiskScore,
                    title: "IP风险评分".to_string(),
                    critical: false,
                    status: LightStatus::Pending,
                    summary: "待定（未获取到出口 IP）".to_string(),
                    error: None,
                    latency_ms: None,
                },
                None,
            )
        };
        report.items[2] = item03;
        report.risk_score = score_opt;
        on_progress(&report);

        // ---- 第 04 项：Claude 可访问 ----
        report.items[3].status = LightStatus::Checking;
        report.items[3].summary = "正在验证 Claude 站点连通性...".to_string();
        on_progress(&report);

        let item04 = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Err(Self::cancelled_err()),
            res = run_step_04_claude_access(&no_redirect_client, &self.endpoints, &self.logger) => res,
        };
        report.items[3] = item04;
        on_progress(&report);

        // ---- 第 05 项：DNS 泄露检测 ----
        report.items[4].status = LightStatus::Checking;
        report.items[4].summary = "正在验证远端 DNS 解析隔离...".to_string();
        on_progress(&report);

        let item05 = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return Err(Self::cancelled_err()),
            res = run_step_05_dns_leak(
                &http_client,
                report.country_code.as_deref(),
                &self.endpoints,
                &self.logger,
            ) => res,
        };
        report.items[4] = item05;

        report.is_running = false;
        report.completed_at = Some(Local::now().format("%H:%M:%S").to_string());

        self.logger.info(
            LogKind::Check,
            format!(
                "五项检测完成: 关键项全绿={}, 出口IP={}, 国家={}, 风险分={:?}",
                report.critical_all_green(),
                report.exit_ip.as_deref().unwrap_or("-"),
                report.country_display.as_deref().unwrap_or("-"),
                report.risk_score
            ),
        );

        self.save_and_emit(&report, &on_progress);

        if let ForwarderHolder::Temp(ephemeral) = holder {
            ephemeral.shutdown().await;
        }

        Ok(report)
    }

    /// 供阶段 3 `Watchdog` 调用的后台轻量巡检（校验出口 IP 基线一致性 + DNS 泄露）
    pub async fn run_watchdog_probe(
        &self,
        forwarder_port: u16,
        baseline_ip: &str,
        baseline_country: Option<&str>,
    ) -> WatchdogProbeOutcome {
        let Ok(client) =
            build_proxied_http_client(forwarder_port, self.endpoints.item_timeout, true)
        else {
            return WatchdogProbeOutcome::TransientOrDisconnected {
                detail: "构建巡检代理客户端失败".to_string(),
            };
        };

        // 1. 探测当前代理出口 IP
        let Some(current_ip) = fetch_fast_exit_ip(&client, &self.endpoints).await else {
            return WatchdogProbeOutcome::TransientOrDisconnected {
                detail: "无法通过本地转发器获取出口 IP（代理可能已断开或超时）".to_string(),
            };
        };

        // 比对出口 IP 是否异常偏离启动基线（静态住宅代理在单次会话中 IP 应恒定；偏离或回落直连即视为泄露风险）
        if current_ip != baseline_ip {
            return WatchdogProbeOutcome::ExplicitLeak {
                reason: "检测到 IP/DNS 泄露，已强制关闭安全浏览器".to_string(),
                detail: format!(
                    "会话出口 IP 偏离基线: 启动基线={}, 当前检测={}",
                    baseline_ip, current_ip
                ),
            };
        }

        // 2. 复测 DNS 出口是否走代理而非本地 ISP DNS
        let dns_item =
            run_step_05_dns_leak(&client, baseline_country, &self.endpoints, &self.logger).await;
        if dns_item.status == LightStatus::Red {
            return WatchdogProbeOutcome::ExplicitLeak {
                reason: "检测到 IP/DNS 泄露，已强制关闭安全浏览器".to_string(),
                detail: dns_item.summary,
            };
        }

        // 3. 复测 Claude 站点可访问性（若不可访问则触发巡检异常系统通知）
        if let Ok(no_redir_client) =
            build_proxied_http_client(forwarder_port, self.endpoints.item_timeout, false)
        {
            let claude_item =
                run_step_04_claude_access(&no_redir_client, &self.endpoints, &self.logger).await;
            if claude_item.status == LightStatus::Red {
                return WatchdogProbeOutcome::ClaudeUnreachable {
                    detail: claude_item.summary,
                };
            }
        }

        WatchdogProbeOutcome::Healthy { current_ip }
    }

    fn save_and_emit<F>(&self, report: &CheckReport, on_progress: &F)
    where
        F: Fn(&CheckReport),
    {
        if let Ok(mut guard) = self.latest_report.lock() {
            *guard = Some(report.clone());
        }
        on_progress(report);
    }

    fn cancelled_err() -> HumanizedError {
        HumanizedError::new(
            "CHECK_CANCELLED",
            "上一轮检测已取消",
            "Check task cancelled by newer request or user action",
            None,
        )
    }
}

/// 构建严格走 `socks5h://127.0.0.1:<port>` 且禁用一切直连绕过的 `reqwest::Client`
pub fn build_proxied_http_client(
    forwarder_port: u16,
    timeout: Duration,
    follow_redirects: bool,
) -> Result<reqwest::Client, HumanizedError> {
    let proxy_url = format!("socks5h://127.0.0.1:{}", forwarder_port);
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| {
        HumanizedError::new(
            "CLIENT_INIT_ERROR",
            "初始化检测客户端失败",
            e.to_string(),
            None,
        )
    })?;

    let redirect_policy = if follow_redirects {
        Policy::limited(4)
    } else {
        Policy::none()
    };

    reqwest::Client::builder()
        .proxy(proxy)
        .redirect(redirect_policy)
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(BROWSER_USER_AGENT)
        .build()
        .map_err(|e| {
            HumanizedError::new(
                "CLIENT_INIT_ERROR",
                "构建检测 HTTP 客户端失败",
                e.to_string(),
                None,
            )
        })
}

/// 第 01 项：经本地 Forwarder 完成一次标准 SOCKS5 握手与目标 `CONNECT`
async fn run_step_01_connection(
    core: &RunningForwarderCore,
    probe_host: &str,
    probe_port: u16,
    timeout: Duration,
    logger: &Logger,
) -> CheckItemResult {
    let _ = core.take_last_upstream_error();
    let started = Instant::now();

    let probe_res = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, core.port())).await?;
        let _ = stream.set_nodelay(true);

        // 下游无认证握手
        stream
            .write_all(&[SOCKS5_VERSION, 0x01, AUTH_METHOD_NONE])
            .await?;
        let mut method_ans = [0u8; 2];
        stream.read_exact(&mut method_ans).await?;
        if method_ans != [SOCKS5_VERSION, AUTH_METHOD_NONE] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "local forwarder rejected greeting",
            ));
        }

        let target = TargetAddr::from_host_port(probe_host, probe_port)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let req = build_socks5_connect_request(&target)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        stream.write_all(&req).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        // 读取剩余绑定地址
        match head[3] {
            ATYP_IPV4 => {
                let mut tail = [0u8; 6];
                let _ = stream.read_exact(&mut tail).await;
            }
            ATYP_IPV6 => {
                let mut tail = [0u8; 18];
                let _ = stream.read_exact(&mut tail).await;
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).await.is_ok() {
                    let mut tail = vec![0u8; len[0] as usize + 2];
                    let _ = stream.read_exact(&mut tail).await;
                }
            }
            _ => {}
        }

        Ok::<u8, std::io::Error>(head[1])
    })
    .await;

    let elapsed_ms = started.elapsed().as_millis() as u64;

    match probe_res {
        Ok(Ok(REP_SUCCEEDED)) => CheckItemResult {
            index: 1,
            id: CheckId::ProxyConnection,
            title: "代理连接".to_string(),
            critical: true,
            status: LightStatus::Green,
            summary: format!("连接正常 ({} ms)", elapsed_ms),
            error: None,
            latency_ms: Some(elapsed_ms),
        },
        Ok(Ok(rep_code)) => {
            let up_err = core.take_last_upstream_error().unwrap_or(UpstreamError::TargetRejected {
                rep: rep_code,
                description: format!("下游收到 SOCKS5 错误码 0x{:02X}", rep_code),
            });
            let category = up_err.short_category();
            let human = HumanizedError::from_upstream_error(&up_err, Some(logger));
            CheckItemResult {
                index: 1,
                id: CheckId::ProxyConnection,
                title: "代理连接".to_string(),
                critical: true,
                status: LightStatus::Red,
                summary: category.to_string(),
                error: Some(human),
                latency_ms: Some(elapsed_ms),
            }
        }
        Ok(Err(io_err)) => {
            let up_err = core
                .take_last_upstream_error()
                .unwrap_or_else(|| UpstreamError::ProxyUnreachable(io_err.to_string()));
            let category = up_err.short_category();
            let human = HumanizedError::from_upstream_error(&up_err, Some(logger));
            CheckItemResult {
                index: 1,
                id: CheckId::ProxyConnection,
                title: "代理连接".to_string(),
                critical: true,
                status: LightStatus::Red,
                summary: category.to_string(),
                error: Some(human),
                latency_ms: Some(elapsed_ms),
            }
        }
        Err(_) => {
            let up_err = core
                .take_last_upstream_error()
                .unwrap_or(UpstreamError::ConnectTimeout);
            let human = HumanizedError::from_upstream_error(&up_err, Some(logger));
            CheckItemResult {
                index: 1,
                id: CheckId::ProxyConnection,
                title: "代理连接".to_string(),
                critical: true,
                status: LightStatus::Red,
                summary: "连接超时".to_string(),
                error: Some(human),
                latency_ms: Some(elapsed_ms),
            }
        }
    }
}

struct GeoIpStepOutcome {
    item: CheckItemResult,
    exit_ip: Option<String>,
    country_code: Option<String>,
    country_display: Option<String>,
    isp: Option<String>,
}

/// 第 02 项：出口 IP 与归属国家检测
async fn run_step_02_geo_ip(
    client: &reqwest::Client,
    endpoints: &CheckEndpointsConfig,
    logger: &Logger,
) -> GeoIpStepOutcome {
    let started = Instant::now();
    let mut last_err_detail = String::new();

    for url in &endpoints.geo_ip_urls {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    // ipwho.is 在失败时返回 {"success": false, ...}
                    if json.get("success") == Some(&serde_json::Value::Bool(false)) {
                        last_err_detail = format!("{}: success=false", url);
                        continue;
                    }

                    let ip_opt = json
                        .get("ip")
                        .or_else(|| json.get("query"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());

                    let code_opt = json
                        .get("country_code")
                        .or_else(|| json.get("countryCode"))
                        .or_else(|| {
                            // ipinfo.io 的 country 字段本身就是两位代码如 "US"
                            json.get("country")
                                .and_then(|v| v.as_str())
                                .filter(|s| s.len() == 2)
                                .map(|_| json.get("country").unwrap())
                        })
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_uppercase());

                    let isp_opt = json
                        .get("isp")
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            json.get("connection")
                                .and_then(|c| c.get("isp"))
                                .and_then(|v| v.as_str())
                        })
                        .or_else(|| json.get("org").and_then(|v| v.as_str()))
                        .map(|s| s.trim().to_string());

                    if let (Some(ip), Some(code)) = (ip_opt, code_opt) {
                        let elapsed_ms = started.elapsed().as_millis() as u64;
                        let display = format_country_display(&code);
                        let is_blocked = UNSUPPORTED_COUNTRY_CODES.contains(&code.as_str());

                        if is_blocked {
                            let err = HumanizedError::new(
                                "UNSUPPORTED_REGION",
                                format!(
                                    "当前出口位于受限地区 ({}) → Claude 不支持该地区访问，请更换美/英/日/新等支持地区的节点",
                                    display
                                ),
                                format!("Exit IP {} resolved to blocked country_code={}", ip, code),
                                Some(logger),
                            );
                            return GeoIpStepOutcome {
                                item: CheckItemResult {
                                    index: 2,
                                    id: CheckId::ExitIpCountry,
                                    title: "出口IP国家".to_string(),
                                    critical: true,
                                    status: LightStatus::Red,
                                    summary: format!("{} · {} (受限地区)", ip, display),
                                    error: Some(err),
                                    latency_ms: Some(elapsed_ms),
                                },
                                exit_ip: Some(ip),
                                country_code: Some(code),
                                country_display: Some(display),
                                isp: isp_opt,
                            };
                        }

                        return GeoIpStepOutcome {
                            item: CheckItemResult {
                                index: 2,
                                id: CheckId::ExitIpCountry,
                                title: "出口IP国家".to_string(),
                                critical: true,
                                status: LightStatus::Green,
                                summary: format!("{} · {}", ip, display),
                                error: None,
                                latency_ms: Some(elapsed_ms),
                            },
                            exit_ip: Some(ip),
                            country_code: Some(code),
                            country_display: Some(display),
                            isp: isp_opt,
                        };
                    }
                }
            }
            Ok(resp) => {
                last_err_detail = format!("{} returned HTTP {}", url, resp.status());
            }
            Err(e) => {
                last_err_detail = format!("{} error: {}", url, e);
            }
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    GeoIpStepOutcome {
        item: CheckItemResult {
            index: 2,
            id: CheckId::ExitIpCountry,
            title: "出口IP国家".to_string(),
            critical: true,
            status: LightStatus::Red,
            summary: "无法查询出口 IP".to_string(),
            error: Some(HumanizedError::new(
                "GEO_IP_FAILED",
                "未能通过代理确认出口 IP 与国家归属 → 请检查代理是否能正常访问外网 HTTPS 接口",
                last_err_detail,
                Some(logger),
            )),
            latency_ms: Some(elapsed_ms),
        },
        exit_ip: None,
        country_code: None,
        country_display: None,
        isp: None,
    }
}

/// 第 03 项：IP 风险评分与机房/纯净度评估（非关键项 / 警告）
async fn run_step_03_ip_risk(
    client: &reqwest::Client,
    exit_ip: &str,
    endpoints: &CheckEndpointsConfig,
    logger: &Logger,
) -> (CheckItemResult, Option<u32>) {
    let started = Instant::now();
    let primary_url = endpoints.ip_risk_primary_template.replace("{ip}", exit_ip);

    // 1. 优先尝试主风险接口 (ipapi.is)
    if let Ok(resp) = client.get(&primary_url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let is_dc = json
                    .get("is_datacenter")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_proxy = json
                    .get("is_proxy")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_vpn = json
                    .get("is_vpn")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_tor = json
                    .get("is_tor")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_abuser = json
                    .get("is_abuser")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let mut score: u32 = 12;
                let mut tags: Vec<&str> = Vec::new();
                if is_dc {
                    score += 40;
                    tags.push("机房/IDC");
                }
                if is_vpn {
                    score += 20;
                    tags.push("VPN特征");
                }
                if is_proxy {
                    score += 25;
                    tags.push("公开代理");
                }
                if is_abuser || is_tor {
                    score += 35;
                    tags.push("高滥用记录");
                }
                score = score.min(100);

                // 若接口显式给了 numeric risk_score 字段（便于自定义替换 API），直接采用
                if let Some(explicit_score) = json.get("risk_score").and_then(|v| v.as_u64()) {
                    score = (explicit_score as u32).min(100);
                }

                return build_risk_item(score, &tags, started.elapsed().as_millis() as u64, logger);
            }
        }
    }

    // 2. 自动容灾回退接口 (ip-api.com hosting/proxy 字段)
    let fallback_url = endpoints
        .ip_risk_fallback_template
        .replace("{ip}", exit_ip);
    if let Ok(resp) = client.get(&fallback_url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if json.get("status").and_then(|v| v.as_str()) == Some("success") {
                    let hosting = json
                        .get("hosting")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let proxy = json
                        .get("proxy")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let mut score: u32 = 15;
                    let mut tags: Vec<&str> = Vec::new();
                    if hosting {
                        score += 45;
                        tags.push("机房托管IP");
                    }
                    if proxy {
                        score += 25;
                        tags.push("代理标记");
                    }
                    score = score.min(100);
                    return build_risk_item(
                        score,
                        &tags,
                        started.elapsed().as_millis() as u64,
                        logger,
                    );
                }
            }
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    (
        CheckItemResult {
            index: 3,
            id: CheckId::IpRiskScore,
            title: "IP风险评分".to_string(),
            critical: false,
            status: LightStatus::Yellow,
            summary: "风险评分接口暂忙（建议确认是否为住宅 IP）".to_string(),
            error: Some(HumanizedError::new(
                "IP_RISK_UNAVAILABLE",
                "第三方 IP 风险库响应超时 → 不阻断使用，但建议优先选用静态住宅 IP 降低风控概率",
                "Primary & fallback IP reputation endpoints timed out or rate-limited",
                Some(logger),
            )),
            latency_ms: Some(elapsed_ms),
        },
        None,
    )
}

fn build_risk_item(
    score: u32,
    tags: &[&str],
    elapsed_ms: u64,
    logger: &Logger,
) -> (CheckItemResult, Option<u32>) {
    if score > IP_RISK_WARN_THRESHOLD {
        let reason_tags = if tags.is_empty() {
            "风险评分偏高".to_string()
        } else {
            tags.join(" / ")
        };
        let detail = format!("Risk Score: {}/100, Flags: {}", score, reason_tags);
        (
            CheckItemResult {
                index: 3,
                id: CheckId::IpRiskScore,
                title: "IP风险评分".to_string(),
                critical: false,
                status: LightStatus::Yellow,
                summary: format!("风险分 {} · {}", score, reason_tags),
                error: Some(HumanizedError::low_ip_reputation(&detail, Some(logger))),
                latency_ms: Some(elapsed_ms),
            },
            Some(score),
        )
    } else {
        (
            CheckItemResult {
                index: 3,
                id: CheckId::IpRiskScore,
                title: "IP风险评分".to_string(),
                critical: false,
                status: LightStatus::Green,
                summary: format!("纯净度良好 (风险分 {}/100)", score),
                error: None,
                latency_ms: Some(elapsed_ms),
            },
            Some(score),
        )
    }
}

/// 第 04 项：Claude 可访问性检测（关键项 / 阻断）
async fn run_step_04_claude_access(
    no_redirect_client: &reqwest::Client,
    endpoints: &CheckEndpointsConfig,
    logger: &Logger,
) -> CheckItemResult {
    let started = Instant::now();
    match no_redirect_client.get(&endpoints.claude_url).send().await {
        Ok(resp) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            let code = resp.status().as_u16();
            let cf_mitigated = resp
                .headers()
                .get("cf-mitigated")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .eq_ignore_ascii_case("challenge");

            if code == 403 || code == 429 || cf_mitigated {
                return CheckItemResult {
                    index: 4,
                    id: CheckId::ClaudeAccess,
                    title: "Claude可访问".to_string(),
                    critical: true,
                    status: LightStatus::Red,
                    summary: format!("被拦截 (HTTP {})", code),
                    error: Some(HumanizedError::claude_forbidden(
                        &format!(
                            "GET {} -> HTTP {} (cf-mitigated={})",
                            endpoints.claude_url, code, cf_mitigated
                        ),
                        Some(logger),
                    )),
                    latency_ms: Some(elapsed_ms),
                };
            }

            if (200..400).contains(&code) {
                return CheckItemResult {
                    index: 4,
                    id: CheckId::ClaudeAccess,
                    title: "Claude可访问".to_string(),
                    critical: true,
                    status: LightStatus::Green,
                    summary: format!("可正常访问 (HTTP {}, {} ms)", code, elapsed_ms),
                    error: None,
                    latency_ms: Some(elapsed_ms),
                };
            }

            CheckItemResult {
                index: 4,
                id: CheckId::ClaudeAccess,
                title: "Claude可访问".to_string(),
                critical: true,
                status: LightStatus::Red,
                summary: format!("响应异常 (HTTP {})", code),
                error: Some(HumanizedError::new(
                    "CLAUDE_HTTP_ERROR",
                    format!(
                        "访问 Claude 返回异常状态码 ({}) → 请稍后重试或更换代理节点",
                        code
                    ),
                    format!("GET {} -> HTTP {}", endpoints.claude_url, code),
                    Some(logger),
                )),
                latency_ms: Some(elapsed_ms),
            }
        }
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            CheckItemResult {
                index: 4,
                id: CheckId::ClaudeAccess,
                title: "Claude可访问".to_string(),
                critical: true,
                status: LightStatus::Red,
                summary: "连接失败或超时".to_string(),
                error: Some(HumanizedError::new(
                    "CLAUDE_UNREACHABLE",
                    "经代理连接 claude.ai 失败或超时 → 请检查该代理节点是否封禁了目标站点或更换节点",
                    e.to_string(),
                    Some(logger),
                )),
                latency_ms: Some(elapsed_ms),
            }
        }
    }
}

/// 第 05 项：DNS 泄露检测（验证域名由远端代理解析而非本地 ISP DNS）
async fn run_step_05_dns_leak(
    client: &reqwest::Client,
    exit_country_code: Option<&str>,
    endpoints: &CheckEndpointsConfig,
    logger: &Logger,
) -> CheckItemResult {
    let started = Instant::now();
    let rand_token = Uuid::new_v4().simple().to_string();
    let url = match &endpoints.dns_leak_url_override {
        Some(tpl) => tpl.replace("{rand}", &rand_token),
        None => format!("https://{}.{}/json", rand_token, DNS_LEAK_EDNS_DOMAIN_SUFFIX),
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let dns_obj = json.get("dns").unwrap_or(&json);
                let dns_ip = dns_obj
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未知");
                let dns_geo = dns_obj
                    .get("geo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("远端解析器");
                let dns_cc = dns_obj
                    .get("country_code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // 若代理出口不在中国大陆，但递归 DNS 却落在境内 ISP，则判定为明确 DNS 泄露
                let exit_not_cn = exit_country_code
                    .map(|c| !LOCAL_ISP_DNS_COUNTRY_CODES.contains(&c))
                    .unwrap_or(true);
                let dns_is_local_cn = LOCAL_ISP_DNS_COUNTRY_CODES.contains(&dns_cc)
                    || dns_geo.to_ascii_lowercase().contains("china");

                if exit_not_cn && dns_is_local_cn {
                    return CheckItemResult {
                        index: 5,
                        id: CheckId::DnsLeak,
                        title: "DNS泄露".to_string(),
                        critical: false,
                        status: LightStatus::Red,
                        summary: format!("疑似 DNS 泄露 ({})", dns_geo),
                        error: Some(HumanizedError::new(
                            "DNS_LEAK_DETECTED",
                            "检测到 DNS 解析落在境内/本地运营商 → 存在 DNS 泄露风险，建议更换支持远端解析的代理节点",
                            format!("Resolver IP={}, Geo={}", dns_ip, dns_geo),
                            Some(logger),
                        )),
                        latency_ms: Some(elapsed_ms),
                    };
                }

                return CheckItemResult {
                    index: 5,
                    id: CheckId::DnsLeak,
                    title: "DNS泄露".to_string(),
                    critical: false,
                    status: LightStatus::Green,
                    summary: format!("无泄露 (远端 DNS: {})", dns_geo),
                    error: None,
                    latency_ms: Some(elapsed_ms),
                };
            }
        }
        _ => {}
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    CheckItemResult {
        index: 5,
        id: CheckId::DnsLeak,
        title: "DNS泄露".to_string(),
        critical: false,
        status: LightStatus::Yellow,
        summary: "已启用转发器域名透传与浏览器禁本地解析保护".to_string(),
        error: Some(HumanizedError::new(
            "DNS_CHECK_FALLBACK",
            "远端 EDNS 检测节点响应超时 → 本地转发器与安全浏览器已强制禁用本机 DNS，可继续但请留意上游状态",
            format!("EDNS endpoint {} timed out", url),
            Some(logger),
        )),
        latency_ms: Some(elapsed_ms),
    }
}

/// 快速获取当前代理出口纯 IP（供 Watchdog 后台高频低开销巡检）
async fn fetch_fast_exit_ip(
    client: &reqwest::Client,
    endpoints: &CheckEndpointsConfig,
) -> Option<String> {
    for url in &endpoints.fast_ip_urls {
        if let Ok(resp) = client.get(url).send().await {
            if !resp.status().is_success() {
                continue;
            }
            if let Ok(body) = resp.text().await {
                // 兼容 Cloudflare /cdn-cgi/trace 文本格式 (ip=1.2.3.4)
                for line in body.lines() {
                    if let Some(ip_val) = line.strip_prefix("ip=") {
                        let trimmed = ip_val.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
                // 兼容 JSON 格式 {"ip": "1.2.3.4"}
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str()) {
                        let trimmed = ip_str.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn format_country_display(code: &str) -> String {
    let upper = code.trim().to_ascii_uppercase();
    let cn_name = match upper.as_str() {
        "US" => "美国",
        "GB" | "UK" => "英国",
        "JP" => "日本",
        "SG" => "新加坡",
        "KR" => "韩国",
        "TW" => "中国台湾",
        "DE" => "德国",
        "FR" => "法国",
        "NL" => "荷兰",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        "CH" => "瑞士",
        "SE" => "瑞典",
        "IE" => "爱尔兰",
        "IN" => "印度",
        "BR" => "巴西",
        "CN" => "中国大陆",
        "HK" => "中国香港",
        "MO" => "中国澳门",
        "RU" => "俄罗斯",
        _ => return upper,
    };
    format!("{} ({})", cn_name, upper)
}
