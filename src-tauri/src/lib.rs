pub mod autostart;
pub mod browser_launcher;
pub mod checker;
pub mod commands;
pub mod constants;
pub mod crypto;
pub mod diagnostics;
pub mod forwarder;
pub mod human_errors;
pub mod license;
pub mod logger;
pub mod proxy_store;
pub mod socks5;
pub mod tool_launcher;
pub mod tray;
pub mod watchdog;
#[cfg(all(target_os = "windows", target_env = "gnu"))]
pub mod wv2_embedded;

use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

use crate::browser_launcher::BrowserLauncher;
use crate::checker::Checker;
use crate::commands::{
    EVENT_BROWSER_STATE, EVENT_CIRCUIT_BREAKER_STATE, EVENT_FORWARDER_STATE, EVENT_LICENSE_STATE,
    EVENT_WATCHDOG_ALERT,
};
use crate::forwarder::{ForwarderLease, ForwarderManager, ForwarderStateSnapshot, LeaseOwner};
use crate::license::{heartbeat_check_cloud, HeartbeatOutcome};
use crate::logger::{LogKind, Logger};
use crate::proxy_store::{resolve_default_app_data_dir, ProxyStore};
use crate::tray::{focus_main_window, send_windows_notification, TrayManager, TrayVisualState};
use crate::watchdog::Watchdog;

/// 应用全局共享上下文
pub struct AppContext {
    pub logger: Arc<Logger>,
    pub proxy_store: Arc<ProxyStore>,
    pub forwarder_mgr: Arc<ForwarderManager>,
    pub checker: Arc<Checker>,
    pub browser_launcher: Arc<BrowserLauncher>,
    pub watchdog: Arc<Watchdog>,
    pub tray_mgr: Arc<TrayManager>,
    pub background_lease: Mutex<Option<ForwarderLease>>,
}

impl AppContext {
    /// 根据当前熔断态、浏览器运行态与后台转发器状态刷新系统托盘图标与菜单可用性
    pub fn refresh_tray_visual(&self, _app: &AppHandle) {
        let visual = if self.watchdog.is_locked() {
            TrayVisualState::TrippedLocked
        } else if self.browser_launcher.is_running() {
            let safe_mode = self.proxy_store.get_settings().safe_mode_enabled;
            TrayVisualState::ProtectedRunning { safe_mode }
        } else {
            TrayVisualState::Idle
        };
        self.tray_mgr.update_visual(visual);
    }

    /// 释放后台常驻转发器租约（供切换激活节点、修改/删除节点或退出授权前调用）
    pub fn drop_background_forwarder(&self) {
        let old = self
            .background_lease
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(lease) = old {
            lease.release();
        }
    }

    /// 确保当前已授权且激活的代理保持本地常驻转发器（优先监听 127.0.0.1:12223，支持系统托盘后台持续运行）
    pub async fn sync_background_forwarder(&self) {
        if self.watchdog.is_locked() || !self.proxy_store.get_license_status().authorized {
            self.drop_background_forwarder();
            return;
        }

        let Some(upstream) = self.proxy_store.resolve_active_upstream().ok().flatten() else {
            self.drop_background_forwarder();
            return;
        };

        // 若已有同代理节点的常驻租约且转发器仍在运行，直接复用
        let already_matched = {
            let guard = self
                .background_lease
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            guard
                .as_ref()
                .map(|l| l.core().proxy_id == upstream.id)
                .unwrap_or(false)
                && matches!(
                    self.forwarder_mgr.snapshot(),
                    ForwarderStateSnapshot::Running { .. }
                )
        };
        if already_matched {
            return;
        }

        self.drop_background_forwarder();
        if let Ok(lease) = self
            .forwarder_mgr
            .acquire_lease(upstream, LeaseOwner::BackgroundDaemon)
            .await
        {
            let mut guard = self
                .background_lease
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *guard = Some(lease);
        }
    }

    /// 安全彻底退出前清理：释放后台常驻租约 → 停止巡检 → 终止安全浏览器进程树 → 停止本地转发器全部连接
    pub fn graceful_shutdown_all(&self) {
        self.drop_background_forwarder();
        self.watchdog.stop_monitoring();
        self.browser_launcher.force_kill("应用正在安全退出");
        self.forwarder_mgr.shutdown_all();
        self.logger.info(LogKind::App, "Claude Safe Lite v2 已清理全部资源并安全退出");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_data_dir = resolve_default_app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir().join("ClaudeSafeLiteFallback"));
    let logger =
        Arc::new(Logger::new(&app_data_dir).expect("初始化 ClaudeSafeLite 日志目录失败"));
    let proxy_store = Arc::new(
        ProxyStore::load_or_init(app_data_dir, logger.clone())
            .expect("初始化 ClaudeSafeLite 配置中心失败"),
    );
    let forwarder_mgr = ForwarderManager::new(logger.clone());
    let checker = Checker::new(forwarder_mgr.clone(), logger.clone());
    let browser_launcher = BrowserLauncher::new(logger.clone());
    let watchdog = Watchdog::new(
        forwarder_mgr.clone(),
        browser_launcher.clone(),
        checker.clone(),
        logger.clone(),
    );
    let tray_mgr = Arc::new(TrayManager::new());

    logger.info(LogKind::App, "Claude Safe Lite v2 后端引擎启动完成");

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main_window(app);
        }))
        .plugin(tauri_plugin_notification::init())
        .manage(AppContext {
            logger,
            proxy_store,
            forwarder_mgr,
            checker,
            browser_launcher,
            watchdog,
            tray_mgr,
            background_lease: Mutex::new(None),
        })
        .setup(|app| {
            let handle = app.handle().clone();
            let ctx = app.state::<AppContext>();

            #[cfg(windows)]
            crate::autostart::ensure_windows_notification_aumid(
                "com.claudesafelite.app",
                "Claude安全客户端",
            );

            // 若配置中开启了开机自启，静默对齐当前可执行文件路径（防止移动 Portable.exe 后路径失效）
            if ctx.proxy_store.get_settings().auto_start_enabled {
                let _ = crate::autostart::apply_system_autostart(true);
            }

            // 1. 初始化系统托盘
            if let Err(err) = ctx.tray_mgr.init(&handle) {
                ctx.logger
                    .warn(LogKind::App, format!("初始化系统托盘失败: {}", err));
            }

            // 2. 绑定状态推送事件到前端 WebView
            {
                let h = handle.clone();
                ctx.forwarder_mgr.set_state_listener(move |snap| {
                    let _ = h.emit(EVENT_FORWARDER_STATE, snap);
                });
            }
            {
                let h = handle.clone();
                ctx.browser_launcher.set_state_listener(move |st| {
                    let _ = h.emit(EVENT_BROWSER_STATE, st);
                });
            }
            {
                // 安全浏览器自然退出时：刷新系统托盘状态；若后台转发器未开启安全模式则停止巡检，否则维持后台巡检守护
                let h = handle.clone();
                ctx.browser_launcher.set_natural_exit_hook(move || {
                    if let Some(c) = h.try_state::<AppContext>() {
                        if !c.proxy_store.get_settings().safe_mode_enabled
                            || !matches!(
                                c.forwarder_mgr.snapshot(),
                                ForwarderStateSnapshot::Running { .. }
                            )
                        {
                            c.watchdog.stop_monitoring();
                        }
                        c.refresh_tray_visual(&h);
                    }
                });
            }
            {
                let h = handle.clone();
                ctx.watchdog.set_state_listener(move |snap| {
                    let _ = h.emit(EVENT_CIRCUIT_BREAKER_STATE, snap);
                });
            }
            {
                // 触发安全熔断时：推送系统原生通知气泡 + 前端弹窗事件 + 切换托盘告警红标
                let h = handle.clone();
                ctx.watchdog.set_alert_listener(move |alert| {
                    send_windows_notification(
                        &h,
                        &alert.notification_title,
                        &alert.notification_body,
                    );
                    let _ = h.emit(EVENT_WATCHDOG_ALERT, &alert);
                    if let Some(c) = h.try_state::<AppContext>() {
                        c.drop_background_forwarder();
                        c.refresh_tray_visual(&h);
                    }
                });
            }
            {
                // 后台巡检检测到非熔断类异常（如 Claude 站点不可访问）时发送系统原生通知提醒用户
                let h = handle.clone();
                ctx.watchdog.set_warning_listener(move |title, body| {
                    send_windows_notification(&h, &title, &body);
                });
            }

            // 3. 启动后自动拉起激活代理的 127.0.0.1:12223 本地常驻转发器，并静默向云端复验一次授权状态
            {
                let h = handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(c) = h.try_state::<AppContext>() {
                        c.sync_background_forwarder().await;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let Some(c) = h.try_state::<AppContext>() else {
                        return;
                    };
                    let Some(stored) = c.proxy_store.get_stored_license_payload() else {
                        return;
                    };
                    let temp_lease = match c.proxy_store.resolve_active_upstream().ok().flatten() {
                        Some(up) => c
                            .forwarder_mgr
                            .acquire_lease(up, LeaseOwner::CheckOrWatchdog)
                            .await
                            .ok(),
                        None => None,
                    };
                    let port = temp_lease.as_ref().map(|l| l.port());
                    let outcome = heartbeat_check_cloud(&stored, port).await;
                    drop(temp_lease);

                    match outcome {
                        HeartbeatOutcome::Valid(refreshed) => {
                            if let Ok(view) = c.proxy_store.save_verified_license(&refreshed) {
                                let _ = h.emit(EVENT_LICENSE_STATE, view);
                            }
                        }
                        HeartbeatOutcome::RevokedOrInvalid(reason) => {
                            c.drop_background_forwarder();
                            c.watchdog.stop_monitoring();
                            c.browser_launcher
                                .force_kill("云端授权已被吊销或失效，自动关闭安全浏览器");
                            c.refresh_tray_visual(&h);
                            if let Ok(view) = c.proxy_store.clear_license_with_reason(Some(reason))
                            {
                                let _ = h.emit(EVENT_LICENSE_STATE, view);
                            }
                        }
                        HeartbeatOutcome::TransientNetworkError => {}
                    }
                });
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    let app_handle = window.app_handle();
                    if let Some(ctx) = app_handle.try_state::<AppContext>() {
                        if ctx.proxy_store.get_license_status().authorized {
                            // 点击右上角关闭按钮（X）不退出，隐藏到系统托盘并保持 127.0.0.1:12223 本地转发器与巡检在后台持续运行
                            api.prevent_close();
                            let _ = window.hide();
                        } else {
                            ctx.graceful_shutdown_all();
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_state,
            commands::activate_license,
            commands::deactivate_license,
            commands::update_settings,
            commands::set_browser_path,
            commands::list_proxies,
            commands::save_proxy,
            commands::duplicate_proxy,
            commands::delete_proxy,
            commands::set_active_proxy,
            commands::parse_proxy_text,
            commands::test_proxy_connection,
            commands::run_checks,
            commands::cancel_checks,
            commands::launch_browser,
            commands::close_browser,
            commands::create_browser_env,
            commands::set_active_browser_env,
            commands::get_diagnostic_report,
            commands::launch_claude_code,
            commands::launch_claude_desktop,
            commands::read_log,
            commands::export_log,
            commands::clear_log,
            commands::reset_env,
            commands::open_external,
            commands::hide_to_tray,
            commands::confirm_exit_app,
        ])
        .build(tauri::generate_context!())
        .expect("构建 Claude Safe Lite v2 应用失败")
        .run(|app_handle, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = event
            {
                focus_main_window(app_handle);
            }
            let _ = (app_handle, event);
        });
}
