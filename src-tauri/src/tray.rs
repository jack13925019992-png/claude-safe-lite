//! 系统托盘状态管理、右键菜单与 Windows 原生告警通知模块（TrayManager）
//!
//! 严格遵循需求文档 5.2：
//! - 托盘图标实时提示当前状态（空闲 / 安全保护中 / 已熔断）；
//! - 右键菜单包含：「显示主窗口」「关闭安全浏览器（仅运行时可用）」「退出程序」；
//! - 支持推送 Windows 原生系统告警通知（`tauri-plugin-notification`）。

use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_notification::NotificationExt;

const MENU_ID_SHOW_MAIN: &str = "tray_show_main";
const MENU_ID_CLOSE_BROWSER: &str = "tray_close_browser";
const MENU_ID_QUIT_APP: &str = "tray_quit_app";

/// 托盘视觉状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayVisualState {
    Idle,
    ProtectedRunning { safe_mode: bool },
    TrippedLocked,
}

pub struct TrayManager {
    inner: Mutex<Option<TrayHandles>>,
}

struct TrayHandles {
    tray: TrayIcon<Wry>,
    close_browser_item: MenuItem<Wry>,
}

impl Default for TrayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrayManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// 在应用 setup 阶段挂载系统托盘与菜单事件
    pub fn init(&self, app: &AppHandle) -> Result<(), String> {
        let show_item = MenuItem::with_id(app, MENU_ID_SHOW_MAIN, "显示主界面", true, None::<&str>)
            .map_err(|e| e.to_string())?;
        let close_browser_item = MenuItem::with_id(
            app,
            MENU_ID_CLOSE_BROWSER,
            "关闭安全浏览器",
            false,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        let quit_item = MenuItem::with_id(
            app,
            MENU_ID_QUIT_APP,
            "彻底退出（关闭转发器）",
            true,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;

        let menu = Menu::with_items(app, &[&show_item, &close_browser_item, &quit_item])
            .map_err(|e| e.to_string())?;

        let initial_icon = generate_shield_rgba_icon(139, 148, 158);

        let tray = TrayIconBuilder::with_id("main-tray")
            .icon(initial_icon)
            .tooltip("Claude安全客户端 - 空闲")
            .menu(&menu)
            .show_menu_on_left_click(cfg!(target_os = "macos"))
            .on_menu_event(|app_handle, event| match event.id().as_ref() {
                MENU_ID_SHOW_MAIN => {
                    focus_main_window(app_handle);
                }
                MENU_ID_CLOSE_BROWSER => {
                    if let Some(ctx) = app_handle.try_state::<crate::AppContext>() {
                        ctx.watchdog.stop_monitoring();
                        ctx.browser_launcher.force_kill("用户通过系统托盘关闭安全浏览器");
                        ctx.refresh_tray_visual(app_handle);
                    }
                }
                MENU_ID_QUIT_APP => {
                    if let Some(ctx) = app_handle.try_state::<crate::AppContext>() {
                        ctx.graceful_shutdown_all();
                    }
                    app_handle.exit(0);
                }
                _ => {}
            })
            .on_tray_icon_event(|tray_icon, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    focus_main_window(tray_icon.app_handle());
                }
            })
            .build(app)
            .map_err(|e| e.to_string())?;

        if let Ok(mut g) = self.inner.lock() {
            *g = Some(TrayHandles {
                tray,
                close_browser_item,
            });
        }

        Ok(())
    }

    /// 同步刷新托盘图标颜色、悬停提示文案与「关闭安全浏览器」菜单可用状态
    pub fn update_visual(&self, state: TrayVisualState) {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(ref handles) = *guard else {
            return;
        };

        let (icon, tooltip, can_close_browser) = match state {
            TrayVisualState::Idle => (
                generate_shield_rgba_icon(139, 148, 158),
                "Claude安全客户端 · 空闲就绪",
                false,
            ),
            TrayVisualState::ProtectedRunning { safe_mode: true } => (
                generate_shield_rgba_icon(46, 160, 67),
                "Claude安全客户端 · 安全保护运行中",
                true,
            ),
            TrayVisualState::ProtectedRunning { safe_mode: false } => (
                generate_shield_rgba_icon(88, 166, 255),
                "Claude安全客户端 · 浏览器运行中（安全模式已关）",
                true,
            ),
            TrayVisualState::TrippedLocked => (
                generate_shield_rgba_icon(248, 81, 73),
                "Claude安全客户端 · 【已触发安全熔断 - 请重新检测解锁】",
                false,
            ),
        };

        let _ = handles.tray.set_icon(Some(icon));
        let _ = handles.tray.set_tooltip(Some(tooltip));
        let _ = handles.close_browser_item.set_enabled(can_close_browser);
    }
}

/// 唤醒并置顶聚焦主窗口
pub fn focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// 发送跨平台系统原生告警通知（Windows WinRT Toast 自动注册 AUMID + macOS Notification Center 兜底）
pub fn send_windows_notification(app: &AppHandle, title: &str, body: &str) {
    if app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .is_ok()
    {
        return;
    }

    #[cfg(windows)]
    {
        crate::autostart::ensure_windows_notification_aumid(
            "com.claudesafelite.app",
            "Claude安全客户端",
        );
        let _ = app.notification().builder().title(title).body(body).show();
    }

    #[cfg(target_os = "macos")]
    {
        let esc_title = title.replace('\\', "\\\\").replace('"', "\\\"");
        let esc_body = body.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            esc_body, esc_title
        );
        let _ = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// 纯内存生成 32x32 抗锯齿双层圆环状态图标（零外部图片文件 IO 依赖）
fn generate_shield_rgba_icon(r: u8, g: u8, b: u8) -> Image<'static> {
    const SIZE: usize = 32;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    let center = 15.5f32;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = (y * SIZE + x) * 4;

            if dist <= 8.5 {
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            } else if dist <= 13.8 {
                rgba[idx] = 18;
                rgba[idx + 1] = 26;
                rgba[idx + 2] = 38;
                rgba[idx + 3] = 245;
            } else if dist <= 15.0 {
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 190;
            }
        }
    }

    Image::new_owned(rgba, SIZE as u32, SIZE as u32)
}
