//! Tauri 前后端命令契约实现（严格对齐需求文档 8.2 & 4.4）

use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::browser_launcher::{BrowserLifecycleState, DetectedBrowser};
use crate::checker::{CheckItemResult, CheckReport};
use crate::constants::PREFLIGHT_CHECK_TIMEOUT_SECS;
use crate::forwarder::{ForwarderStateSnapshot, LeaseOwner};
use crate::human_errors::HumanizedError;
use crate::license::LicenseStatusView;
use crate::logger::{LogKind, LogLevel};
use crate::proxy_store::{
    AppSettings, BrowserProfileEnv, ParsedProxyDraft, ProxyView, SaveProxyInput, StoreError,
};
use crate::tool_launcher::{
    execute_reset_environment, launch_claude_code_cli, launch_claude_desktop_app,
    open_external_https_url, show_save_log_dialog, ResetEnvOptions, ResetSummary,
};
use crate::watchdog::CircuitBreakerSnapshot;
use crate::AppContext;

pub const EVENT_CHECK_PROGRESS: &str = "check-progress";
pub const EVENT_BROWSER_STATE: &str = "browser-state";
pub const EVENT_FORWARDER_STATE: &str = "forwarder-state";
pub const EVENT_CIRCUIT_BREAKER_STATE: &str = "circuit-breaker-state";
pub const EVENT_WATCHDOG_ALERT: &str = "watchdog-alert";
pub const EVENT_WINDOW_CLOSE_REQUESTED: &str = "window-close-requested";
pub const EVENT_LICENSE_STATE: &str = "license-state";

/// 首屏聚合全局状态响应
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppFullStateResponse {
    pub license: LicenseStatusView,
    pub proxies: Vec<ProxyView>,
    pub active_proxy_id: Option<String>,
    pub settings: AppSettings,
    pub browser_envs: Vec<BrowserProfileEnv>,
    pub active_browser_env_id: String,
    pub browser_state: BrowserLifecycleState,
    pub running_proxy_id: Option<String>,
    pub running_browser_env_id: Option<String>,
    pub forwarder_state: ForwarderStateSnapshot,
    pub circuit_breaker: CircuitBreakerSnapshot,
    pub latest_report: Option<CheckReport>,
    pub recovered_from_backup: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserEnvStateResponse {
    pub browser_envs: Vec<BrowserProfileEnv>,
    pub active_browser_env_id: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateLicenseInput {
    pub name: String,
    pub phone: String,
    pub license_code: String,
    pub proxy_input: Option<SaveProxyInput>,
}

/// 代理列表响应
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyListResponse {
    pub proxies: Vec<ProxyView>,
    pub active_proxy_id: Option<String>,
}

/// 「启动安全浏览器」返回的多态结构（精准承载阻断、非关键项黄灯二次确认与启动成功）
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum LaunchBrowserResponse {
    #[serde(rename_all = "camelCase")]
    Launched {
        browser: DetectedBrowser,
        forwarder_port: u16,
    },
    #[serde(rename_all = "camelCase")]
    NeedsWarningConfirm {
        warnings: Vec<CheckItemResult>,
        report: CheckReport,
    },
    #[serde(rename_all = "camelCase")]
    Blocked {
        reason: HumanizedError,
        report: Option<CheckReport>,
    },
}

fn map_store_err(err: StoreError, ctx: &AppContext) -> HumanizedError {
    match err {
        StoreError::Validation(msg) | StoreError::ParseError(msg) => {
            HumanizedError::new("VALIDATION_ERROR", msg, "Input validation rejected", Some(&ctx.logger))
        }
        StoreError::License(le) => HumanizedError::new(
            "LICENSE_INVALID",
            le.to_string(),
            "Ed25519 license verification rejected",
            Some(&ctx.logger),
        ),
        StoreError::Unauthorized => HumanizedError::new(
            "LICENSE_UNAUTHORIZED",
            "软件尚未通过授权验证或授权已过期 → 请先在授权访问界面输入有效授权码",
            "ensure_authorized rejected call",
            Some(&ctx.logger),
        ),
        StoreError::ProxyNotFound => HumanizedError::new(
            "PROXY_NOT_FOUND",
            "未找到指定的代理配置，可能已被删除",
            "Proxy ID not found",
            Some(&ctx.logger),
        ),
        StoreError::Crypto(ce) => HumanizedError::new(
            "DPAPI_CRYPTO_ERROR",
            if cfg!(windows) {
                "系统凭据加密服务 (Windows DPAPI) 调用失败，为保障安全已拒绝明文保存"
            } else {
                "本机安全凭据加密服务调用失败（可能跨设备拷贝了配置），为保障安全已拒绝明文保存"
            },
            ce.to_string(),
            Some(&ctx.logger),
        ),
        other => HumanizedError::new(
            "STORE_IO_ERROR",
            "读写配置文件失败 → 请检查磁盘权限或杀毒软件拦截",
            other.to_string(),
            Some(&ctx.logger),
        ),
    }
}

#[tauri::command]
pub fn get_app_state(ctx: State<'_, AppContext>) -> AppFullStateResponse {
    let license = ctx.proxy_store.get_license_status();
    let (proxies, active_proxy_id) = ctx.proxy_store.list_proxies();
    let settings = ctx.proxy_store.get_settings();
    let (browser_envs, active_browser_env_id) = ctx.proxy_store.list_browser_envs();
    let browser_state = if ctx.browser_launcher.is_running() {
        BrowserLifecycleState::Running
    } else {
        BrowserLifecycleState::Idle
    };

    AppFullStateResponse {
        license,
        proxies,
        active_proxy_id,
        settings,
        browser_envs,
        active_browser_env_id,
        browser_state,
        running_proxy_id: ctx.browser_launcher.running_proxy_id(),
        running_browser_env_id: ctx.browser_launcher.running_env_id(),
        forwarder_state: ctx.forwarder_mgr.snapshot(),
        circuit_breaker: ctx.watchdog.snapshot(),
        latest_report: ctx.checker.latest_report(),
        recovered_from_backup: ctx.proxy_store.take_recovered_notice(),
    }
}

#[tauri::command]
pub async fn activate_license(
    input: ActivateLicenseInput,
    ctx: State<'_, AppContext>,
) -> Result<LicenseStatusView, HumanizedError> {
    // 1. 若登录页填写了代理或本机已有激活代理，准备可选的本地转发器端口供云端核销双通道穿透
    let transient_upstream = if let Some(ref proxy_in) = input.proxy_input {
        Some(
            ctx.proxy_store
                .resolve_transient_upstream(proxy_in)
                .map_err(|e| map_store_err(e, &ctx))?,
        )
    } else {
        ctx.proxy_store.resolve_active_upstream().ok().flatten()
    };

    let temp_lease = match transient_upstream {
        Some(up) => ctx
            .forwarder_mgr
            .acquire_lease(up, LeaseOwner::CheckOrWatchdog)
            .await
            .ok(),
        None => None,
    };
    let fallback_port = temp_lease.as_ref().map(|l| l.port());

    // 2. 向云端发起一机一码核销与 Ed25519 响应签名验证
    let verified_payload = crate::license::activate_with_cloud(
        &input.name,
        &input.phone,
        &input.license_code,
        fallback_port,
    )
    .await
    .map_err(|e| map_store_err(StoreError::License(e), &ctx))?;

    drop(temp_lease);

    // 3. 授权核验通过后，若登录页一并填写了 SOCKS5 代理配置，加密保存并设为激活代理
    if let Some(proxy_in) = input.proxy_input {
        let saved_proxy = ctx
            .proxy_store
            .save_proxy(proxy_in)
            .map_err(|e| map_store_err(e, &ctx))?;
        let _ = ctx
            .proxy_store
            .set_active_proxy(&saved_proxy.id)
            .map_err(|e| map_store_err(e, &ctx))?;
        ctx.logger.info(
            LogKind::App,
            format!("授权登录页已同步保存并激活代理配置: {}", saved_proxy.name),
        );
    }

    // 4. DPAPI 加密持久化本机授权凭证
    let view = ctx
        .proxy_store
        .save_verified_license(&verified_payload)
        .map_err(|e| map_store_err(e, &ctx))?;

    ctx.sync_background_forwarder().await;

    ctx.logger.info(
        LogKind::App,
        format!(
            "云端一机一码授权激活成功: 用户={} | 设备码={} | 到期={}",
            view.holder_name.as_deref().unwrap_or(""),
            view.machine_code,
            view.expires_at.as_deref().unwrap_or("永久有效")
        ),
    );
    Ok(view)
}

#[tauri::command]
pub fn deactivate_license(
    app: AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<LicenseStatusView, HumanizedError> {
    ctx.drop_background_forwarder();
    ctx.watchdog.stop_monitoring();
    if ctx.browser_launcher.is_running() {
        ctx.browser_launcher.force_kill("切换软件授权，自动关闭安全浏览器");
    }
    ctx.refresh_tray_visual(&app);

    let view = ctx
        .proxy_store
        .clear_license_with_reason(None)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.logger.info(LogKind::App, "用户已退出当前软件授权登录态");
    Ok(view)
}

#[tauri::command]
pub fn update_settings(
    settings: AppSettings,
    app: AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<AppSettings, HumanizedError> {
    let prev = ctx.proxy_store.get_settings();
    if prev.auto_start_enabled != settings.auto_start_enabled {
        crate::autostart::apply_system_autostart(settings.auto_start_enabled).map_err(|err| {
            HumanizedError::new(
                "AUTOSTART_ERROR",
                "设置开机自动启动失败 → 请检查安全软件是否拦截了当前用户启动项写入",
                err,
                Some(&ctx.logger),
            )
        })?;
        ctx.logger.info(
            LogKind::App,
            format!(
                "已{}开机自动启动",
                if settings.auto_start_enabled {
                    "开启"
                } else {
                    "关闭"
                }
            ),
        );
    }

    let saved = ctx
        .proxy_store
        .update_settings(settings)
        .map_err(|e| map_store_err(e, &ctx))?;

    // 实时同步更新 Watchdog 开关与周期（无论安全浏览器运行中还是后台转发器运行中）
    if saved.safe_mode_enabled {
        if let ForwarderStateSnapshot::Running { port, .. } = ctx.forwarder_mgr.snapshot() {
            if let Some(rep) = ctx.checker.latest_report() {
                if rep.critical_all_green() {
                    if let Some(ip) = rep.exit_ip {
                        ctx.watchdog.start_monitoring(
                            port,
                            ip,
                            rep.country_code,
                            Duration::from_secs(saved.watchdog_interval_sec),
                        );
                    }
                }
            }
        }
    } else {
        ctx.watchdog.stop_monitoring();
    }

    ctx.refresh_tray_visual(&app);
    Ok(saved)
}

#[tauri::command]
pub fn set_browser_path(
    path: Option<String>,
    app: AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<AppSettings, HumanizedError> {
    let mut current = ctx.proxy_store.get_settings();
    current.custom_browser_path = path;
    update_settings(current, app, ctx)
}

#[tauri::command]
pub fn list_proxies(ctx: State<'_, AppContext>) -> ProxyListResponse {
    let (proxies, active_proxy_id) = ctx.proxy_store.list_proxies();
    ProxyListResponse {
        proxies,
        active_proxy_id,
    }
}

#[tauri::command]
pub async fn save_proxy(
    input: SaveProxyInput,
    ctx: State<'_, AppContext>,
) -> Result<ProxyView, HumanizedError> {
    // 若正在编辑当前安全浏览器运行中的代理，拦截防止运行态连接参数不一致
    if let (Some(ref editing_id), Some(ref running_id)) =
        (&input.id, ctx.browser_launcher.running_proxy_id())
    {
        if editing_id == running_id {
            return Err(HumanizedError::new(
                "PROXY_IN_USE",
                "该代理配置的安全浏览器正在运行中 → 请先关闭安全浏览器后再修改此配置",
                "Cannot mutate currently running browser's proxy config",
                Some(&ctx.logger),
            ));
        }
    }

    let (_, prev_active) = ctx.proxy_store.list_proxies();
    let editing_active = input.id.is_some() && input.id == prev_active;
    if editing_active {
        ctx.watchdog.stop_monitoring();
        ctx.drop_background_forwarder();
    }

    let view = ctx
        .proxy_store
        .save_proxy(input)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.sync_background_forwarder().await;
    ctx.logger
        .info(LogKind::App, format!("已保存代理配置: {}", view.name));
    Ok(view)
}

#[tauri::command]
pub fn duplicate_proxy(id: String, ctx: State<'_, AppContext>) -> Result<ProxyView, HumanizedError> {
    let view = ctx
        .proxy_store
        .duplicate_proxy(&id)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.logger
        .info(LogKind::App, format!("已复制代理配置: {}", view.name));
    Ok(view)
}

#[tauri::command]
pub async fn delete_proxy(
    id: String,
    ctx: State<'_, AppContext>,
) -> Result<Option<String>, HumanizedError> {
    if ctx.browser_launcher.running_proxy_id().as_deref() == Some(id.as_str()) {
        return Err(HumanizedError::new(
            "PROXY_IN_USE",
            "该代理配置的安全浏览器正在运行 → 请先关闭安全浏览器后再删除",
            "Cannot delete active browser proxy",
            Some(&ctx.logger),
        ));
    }

    let (_, prev_active) = ctx.proxy_store.list_proxies();
    if prev_active.as_deref() == Some(id.as_str()) {
        ctx.watchdog.stop_monitoring();
        ctx.drop_background_forwarder();
    }

    let next_active = ctx
        .proxy_store
        .delete_proxy(&id)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.sync_background_forwarder().await;
    ctx.logger
        .info(LogKind::App, format!("已删除代理配置 ID={}", id));
    Ok(next_active)
}

#[tauri::command]
pub async fn set_active_proxy(
    id: String,
    ctx: State<'_, AppContext>,
) -> Result<ProxyView, HumanizedError> {
    if let Some(running_id) = ctx.browser_launcher.running_proxy_id() {
        if running_id != id {
            return Err(HumanizedError::new(
                "BROWSER_RUNNING_SWITCH_BLOCKED",
                "安全浏览器正在运行中 → 请先关闭安全浏览器后再切换激活代理（防止代理环境错乱）",
                format!("Running proxy={} cannot switch to {}", running_id, id),
                Some(&ctx.logger),
            ));
        }
    }

    ctx.watchdog.stop_monitoring();
    ctx.drop_background_forwarder();

    let view = ctx
        .proxy_store
        .set_active_proxy(&id)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.sync_background_forwarder().await;
    ctx.logger
        .info(LogKind::App, format!("已切换当前激活代理为: {}", view.name));
    Ok(view)
}

#[tauri::command]
pub fn parse_proxy_text(
    raw: String,
    ctx: State<'_, AppContext>,
) -> Result<ParsedProxyDraft, HumanizedError> {
    crate::proxy_store::parse_proxy_text(&raw).map_err(|e| map_store_err(e, &ctx))
}

#[tauri::command]
pub async fn test_proxy_connection(
    input: SaveProxyInput,
    ctx: State<'_, AppContext>,
) -> Result<CheckItemResult, HumanizedError> {
    let upstream = ctx
        .proxy_store
        .resolve_transient_upstream(&input)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.checker.test_single_connection(upstream).await
}

#[tauri::command]
pub async fn run_checks(
    app: AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<CheckReport, HumanizedError> {
    ctx.proxy_store
        .ensure_authorized()
        .map_err(|e| map_store_err(e, &ctx))?;

    let upstream = ctx
        .proxy_store
        .resolve_active_upstream()
        .map_err(|e| map_store_err(e, &ctx))?
        .ok_or_else(|| {
            HumanizedError::new(
                "NO_ACTIVE_PROXY",
                "请先添加并保存真实代理配置",
                "activeProxyId is None",
                Some(&ctx.logger),
            )
        })?;

    let app_for_emit = app.clone();
    let report = ctx
        .checker
        .run_all_checks(upstream, move |progress| {
            let _ = app_for_emit.emit(EVENT_CHECK_PROGRESS, progress);
        })
        .await?;

    // 熔断态下：若关键项（01、02、04）全绿且无明确泄露，自动解除熔断锁定！
    if ctx.watchdog.try_unlock_after_recheck(&report) {
        ctx.refresh_tray_visual(&app);
    }

    ctx.sync_background_forwarder().await;

    // 检测关键项全绿且开启安全模式时，自动挂载后台定期安全巡检（即使隐藏到系统托盘未开内置浏览器也能实时告警）
    let settings = ctx.proxy_store.get_settings();
    if settings.safe_mode_enabled && !ctx.watchdog.is_locked() && report.critical_all_green() {
        if let ForwarderStateSnapshot::Running { port, .. } = ctx.forwarder_mgr.snapshot() {
            if let Some(ref ip) = report.exit_ip {
                ctx.watchdog.start_monitoring(
                    port,
                    ip.clone(),
                    report.country_code.clone(),
                    Duration::from_secs(settings.watchdog_interval_sec),
                );
            }
        }
    }

    Ok(report)
}

#[tauri::command]
pub fn cancel_checks(ctx: State<'_, AppContext>) {
    ctx.checker.cancel_current();
}

#[tauri::command]
pub async fn launch_browser(
    force: bool,
    allow_warnings: Option<bool>,
    app: AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<LaunchBrowserResponse, HumanizedError> {
    ctx.proxy_store
        .ensure_authorized()
        .map_err(|e| map_store_err(e, &ctx))?;

    // 1. 熔断锁定态硬性拦截（严禁通过 force 强制启动绕过！需求 4.4 & 5.1）
    if ctx.watchdog.is_locked() {
        return Err(HumanizedError::new(
            "LOCKED_BY_CIRCUIT_BREAKER",
            "安全熔断已触发，请先点击【重新检测】通过后再启动",
            "Circuit breaker is in Tripped/Locked state; force bypass is strictly forbidden",
            Some(&ctx.logger),
        ));
    }

    let upstream = ctx
        .proxy_store
        .resolve_active_upstream()
        .map_err(|e| map_store_err(e, &ctx))?
        .ok_or_else(|| {
            HumanizedError::new(
                "NO_ACTIVE_PROXY",
                "请先添加并保存真实代理配置",
                "No active proxy configured",
                Some(&ctx.logger),
            )
        })?;

    let settings = ctx.proxy_store.get_settings();
    let mut baseline_ip: Option<String> = None;
    let mut baseline_country: Option<String> = None;

    if !force {
        // 检查是否刚刚通过了预检且用户点击了黄灯风险确认弹窗（allow_warnings == Some(true)）
        let reusable_report = if allow_warnings == Some(true) {
            ctx.checker
                .latest_report()
                .filter(|r| r.proxy_id == upstream.id && r.critical_all_green())
        } else {
            None
        };

        let report = if let Some(existing_rep) = reusable_report {
            existing_rep
        } else {
            // 执行启动前预检（总超时上限 15 秒，需求 4.4）
            let app_emit = app.clone();
            let check_fut = ctx.checker.run_all_checks(upstream.clone(), move |p| {
                let _ = app_emit.emit(EVENT_CHECK_PROGRESS, p);
            });

            match tokio::time::timeout(
                Duration::from_secs(PREFLIGHT_CHECK_TIMEOUT_SECS),
                check_fut,
            )
            .await
            {
                Ok(Ok(rep)) => rep,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    ctx.checker.cancel_current();
                    return Err(HumanizedError::new(
                        "PREFLIGHT_TIMEOUT",
                        "启动前安全预检超过 15 秒超时 → 网络或代理节点过于缓慢，请稍后重试或更换节点",
                        "Preflight 5-step check exceeded 15s cap",
                        Some(&ctx.logger),
                    ));
                }
            }
        };

        // 关键项（01、02、04）存在红灯/未通过 → 阻止启动
        if !report.critical_all_green() {
            let first_bad = report
                .items
                .iter()
                .find(|i| i.critical && i.status != crate::checker::LightStatus::Green);
            let reason = first_bad
                .and_then(|i| i.error.clone())
                .unwrap_or_else(|| {
                    HumanizedError::new(
                        "CRITICAL_CHECK_FAILED",
                        "关键安全检测项未通过，已阻止启动安全浏览器 → 请根据红灯提示修复代理或更换节点",
                        "One or more critical checks (01/02/04) failed",
                        Some(&ctx.logger),
                    )
                });
            return Ok(LaunchBrowserResponse::Blocked {
                reason,
                report: Some(report),
            });
        }

        // 关键项全绿，但非关键项（03、05）有黄灯或红灯且尚未经用户确认 → 弹出风险确认框
        let warnings: Vec<CheckItemResult> = report
            .non_critical_warnings()
            .into_iter()
            .cloned()
            .collect();
        if !warnings.is_empty() && allow_warnings != Some(true) {
            return Ok(LaunchBrowserResponse::NeedsWarningConfirm { warnings, report });
        }

        baseline_ip = report.exit_ip.clone();
        baseline_country = report.country_code.clone();
    } else {
        // 强制启动记录写入 launch.log（需求 4.4 第 174 行）
        ctx.logger.log(
            LogKind::Launch,
            LogLevel::Warn,
            &format!(
                "【用户选择忽略检测，强制启动安全浏览器】代理配置: {}",
                upstream.name
            ),
        );
        if let Some(prev) = ctx.checker.latest_report() {
            if prev.proxy_id == upstream.id {
                baseline_ip = prev.exit_ip;
                baseline_country = prev.country_code;
            }
        }
    }

    // 申请共享 Forwarder 租约并启动安全浏览器（注入匹配出口国家的 TZ 时区、--lang=en-US 与独立多账号环境目录）
    let (envs, active_env_id) = ctx.proxy_store.list_browser_envs();
    let active_env_name = envs
        .iter()
        .find(|e| e.id == active_env_id)
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "默认环境".to_string());

    let lease = ctx
        .forwarder_mgr
        .acquire_lease(upstream.clone(), LeaseOwner::SafeBrowser)
        .await?;
    let forwarder_port = lease.port();
    let profile_dir = ctx
        .proxy_store
        .profile_dir_for_env(&upstream.id, &active_env_id);

    let detected = ctx.browser_launcher.launch_isolated_with_env(
        upstream.id.clone(),
        upstream.name.clone(),
        active_env_id,
        active_env_name,
        profile_dir,
        settings.custom_browser_path.as_deref(),
        baseline_country.as_deref(),
        lease,
    )?;

    // 若开启安全模式则启动 Watchdog 后台双引擎巡检
    if settings.safe_mode_enabled {
        let interval = Duration::from_secs(settings.watchdog_interval_sec);
        if let Some(ip) = baseline_ip {
            ctx.watchdog
                .start_monitoring(forwarder_port, ip, baseline_country, interval);
        } else {
            // 强制启动且尚无缓存基线 IP 时：立即后台通过转发器采样基线并开启守护（若连不上同样按防泄露规则熔断！）
            let wd = ctx.watchdog.clone();
            let checker = ctx.checker.clone();
            let up_clone = upstream.clone();
            let app_bg = app.clone();
            tokio::spawn(async move {
                if let Ok(rep) = checker.run_all_checks(up_clone, move |p| {
                    let _ = app_bg.emit(EVENT_CHECK_PROGRESS, p);
                }).await {
                    if let Some(ip) = rep.exit_ip {
                        wd.start_monitoring(forwarder_port, ip, rep.country_code, interval);
                    } else {
                        wd.execute_atomic_trip(
                            crate::watchdog::TripKind::ProxyDisconnected,
                            "强制启动后无法通过代理建立有效安全基线，已触发防直连保护",
                        );
                    }
                }
            });
        }
    }

    ctx.refresh_tray_visual(&app);

    Ok(LaunchBrowserResponse::Launched {
        browser: detected,
        forwarder_port,
    })
}

#[tauri::command]
pub fn close_browser(app: AppHandle, ctx: State<'_, AppContext>) -> bool {
    let killed = ctx
        .browser_launcher
        .force_kill("用户手动点击关闭安全浏览器");
    if !ctx.proxy_store.get_settings().safe_mode_enabled
        || !matches!(
            ctx.forwarder_mgr.snapshot(),
            ForwarderStateSnapshot::Running { .. }
        )
    {
        ctx.watchdog.stop_monitoring();
    }
    ctx.refresh_tray_visual(&app);
    killed
}

#[tauri::command]
pub fn create_browser_env(
    name: String,
    ctx: State<'_, AppContext>,
) -> Result<BrowserEnvStateResponse, HumanizedError> {
    if ctx.browser_launcher.is_running() {
        return Err(HumanizedError::new(
            "BROWSER_RUNNING_ENV_BLOCKED",
            "安全浏览器正在运行中 → 请先关闭当前安全浏览器后再新建并切换独立环境",
            "Cannot switch browser profile env while active session is running",
            Some(&ctx.logger),
        ));
    }

    let (browser_envs, active_browser_env_id) = ctx
        .proxy_store
        .create_browser_env(&name)
        .map_err(|e| map_store_err(e, &ctx))?;
    ctx.logger.info(
        LogKind::App,
        format!("已新建并切换至独立浏览器环境: {}", name.trim()),
    );
    Ok(BrowserEnvStateResponse {
        browser_envs,
        active_browser_env_id,
    })
}

#[tauri::command]
pub fn set_active_browser_env(
    env_id: String,
    ctx: State<'_, AppContext>,
) -> Result<BrowserEnvStateResponse, HumanizedError> {
    if let Some(running_env) = ctx.browser_launcher.running_env_id() {
        if running_env != env_id {
            return Err(HumanizedError::new(
                "BROWSER_RUNNING_ENV_BLOCKED",
                "安全浏览器正在运行中 → 请先关闭当前安全浏览器后再切换其他独立账号环境",
                format!("Running env={} cannot switch to {}", running_env, env_id),
                Some(&ctx.logger),
            ));
        }
    }

    let (browser_envs, active_browser_env_id) = ctx
        .proxy_store
        .set_active_browser_env(&env_id)
        .map_err(|e| map_store_err(e, &ctx))?;
    Ok(BrowserEnvStateResponse {
        browser_envs,
        active_browser_env_id,
    })
}

#[tauri::command]
pub fn get_diagnostic_report(ctx: State<'_, AppContext>) -> String {
    crate::diagnostics::build_sanitized_diagnostic_report(&ctx)
}

#[tauri::command]
pub async fn launch_claude_code(
    workdir: Option<String>,
    ctx: State<'_, AppContext>,
) -> Result<String, HumanizedError> {
    ctx.proxy_store
        .ensure_authorized()
        .map_err(|e| map_store_err(e, &ctx))?;

    if ctx.watchdog.is_locked() {
        return Err(HumanizedError::new(
            "LOCKED_BY_CIRCUIT_BREAKER",
            "安全熔断已触发，请先点击【重新检测】通过解锁后再启动 Claude Code",
            "Circuit breaker locked",
            Some(&ctx.logger),
        ));
    }

    let upstream = ctx
        .proxy_store
        .resolve_active_upstream()
        .map_err(|e| map_store_err(e, &ctx))?
        .ok_or_else(|| {
            HumanizedError::new(
                "NO_ACTIVE_PROXY",
                "请先添加并保存真实代理配置",
                "No active proxy configured",
                Some(&ctx.logger),
            )
        })?;

    launch_claude_code_cli(workdir, upstream, &ctx.forwarder_mgr, &ctx.logger).await
}

#[tauri::command]
pub async fn launch_claude_desktop(ctx: State<'_, AppContext>) -> Result<String, HumanizedError> {
    ctx.proxy_store
        .ensure_authorized()
        .map_err(|e| map_store_err(e, &ctx))?;

    if ctx.watchdog.is_locked() {
        return Err(HumanizedError::new(
            "LOCKED_BY_CIRCUIT_BREAKER",
            "安全熔断已触发，请先点击【重新检测】通过解锁后再启动 Claude 桌面端",
            "Circuit breaker locked",
            Some(&ctx.logger),
        ));
    }

    let upstream = ctx
        .proxy_store
        .resolve_active_upstream()
        .map_err(|e| map_store_err(e, &ctx))?
        .ok_or_else(|| {
            HumanizedError::new(
                "NO_ACTIVE_PROXY",
                "请先添加并保存真实代理配置",
                "No active proxy configured",
                Some(&ctx.logger),
            )
        })?;

    launch_claude_desktop_app(upstream, &ctx.forwarder_mgr, &ctx.logger).await
}

#[tauri::command]
pub fn read_log(
    kind: LogKind,
    tail: Option<usize>,
    ctx: State<'_, AppContext>,
) -> Result<Vec<String>, HumanizedError> {
    ctx.logger.read_tail(kind, tail).map_err(|e| {
        HumanizedError::new(
            "READ_LOG_FAILED",
            "读取日志文件失败",
            e.to_string(),
            Some(&ctx.logger),
        )
    })
}

#[tauri::command]
pub async fn export_log(
    kind: LogKind,
    ctx: State<'_, AppContext>,
) -> Result<Option<String>, HumanizedError> {
    let default_name = format!(
        "claude-safe-lite-{}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        kind.file_name()
    );
    let picked = tokio::task::spawn_blocking(move || show_save_log_dialog(&default_name))
        .await
        .ok()
        .flatten();

    let Some(dest_path) = picked else {
        return Ok(None);
    };

    ctx.logger.export_to(kind, &dest_path).map_err(|e| {
        HumanizedError::new(
            "EXPORT_LOG_FAILED",
            "导出日志文件失败 → 请检查保存路径是否有写入权限",
            e.to_string(),
            Some(&ctx.logger),
        )
    })?;

    Ok(Some(dest_path.to_string_lossy().to_string()))
}

#[tauri::command]
pub fn clear_log(kind: LogKind, ctx: State<'_, AppContext>) -> Result<(), HumanizedError> {
    ctx.logger.clear(kind).map_err(|e| {
        HumanizedError::new(
            "CLEAR_LOG_FAILED",
            "清空日志文件失败",
            e.to_string(),
            Some(&ctx.logger),
        )
    })
}

#[tauri::command]
pub fn reset_env(
    options: ResetEnvOptions,
    ctx: State<'_, AppContext>,
) -> Result<ResetSummary, HumanizedError> {
    if options.clear_proxies {
        ctx.watchdog.stop_monitoring();
        ctx.drop_background_forwarder();
    }
    execute_reset_environment(&options, &ctx.browser_launcher, &ctx.proxy_store, &ctx.logger)
}

#[tauri::command]
pub fn open_external(url: String, ctx: State<'_, AppContext>) -> Result<(), HumanizedError> {
    open_external_https_url(&url, &ctx.logger)
}

#[tauri::command]
pub fn hide_to_tray(app: AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

#[tauri::command]
pub fn confirm_exit_app(app: AppHandle, ctx: State<'_, AppContext>) {
    ctx.graceful_shutdown_all();
    app.exit(0);
}
