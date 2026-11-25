//! 跨平台开机自动启动管理模块（Windows HKCU Run + macOS LaunchAgents）
//!
//! 设计红线：
//! 1. Windows：仅操作当前用户 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，零 UAC 管理员弹窗；
//! 2. macOS：仅操作当前用户 `~/Library/LaunchAgents/com.claudesafelite.app.plist`，零 root 权限弹窗；
//! 3. 全程兼容含中文、空格与特殊字符的安装路径。

use std::path::Path;

pub const AUTOSTART_APP_KEY: &str = "ClaudeSafeLite";
#[cfg(target_os = "macos")]
const MACOS_LAUNCH_AGENT_LABEL: &str = "com.claudesafelite.app";

/// 将开机自动启动状态同步写入当前操作系统用户启动项
pub fn apply_system_autostart(enabled: bool) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("无法获取当前程序可执行文件路径: {}", e))?;
    apply_autostart_for_path(enabled, &exe_path)
}

/// 面向指定可执行文件路径写入或移除开机启动项
pub fn apply_autostart_for_path(enabled: bool, exe_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        apply_windows_hkcu_run(enabled, AUTOSTART_APP_KEY, exe_path)
    }

    #[cfg(target_os = "macos")]
    {
        apply_macos_launch_agent(enabled, exe_path)
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        apply_linux_desktop_autostart(enabled, exe_path)
    }
}

/// 查询当前系统级用户启动项是否已注册
pub fn is_system_autostart_registered() -> bool {
    #[cfg(windows)]
    {
        is_windows_hkcu_run_registered(AUTOSTART_APP_KEY)
    }

    #[cfg(target_os = "macos")]
    {
        macos_plist_path()
            .map(|p| p.is_file())
            .unwrap_or(false)
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        linux_autostart_path()
            .map(|p| p.is_file())
            .unwrap_or(false)
    }
}

#[cfg(windows)]
pub fn apply_windows_hkcu_run(
    enabled: bool,
    value_name: &str,
    exe_path: &Path,
) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let subkey: Vec<u16> = OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_name_wide: Vec<u16> = OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    if enabled {
        let mut hkey: HKEY = ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                ptr::null(),
                &mut hkey,
                ptr::null_mut(),
            )
        };
        if rc != 0 || hkey.is_null() {
            return Err(format!("打开 HKCU Run 注册表项失败 (Win32 Error: {})", rc));
        }

        // 用双引号包裹完整路径，防止空格路径被截断
        let quoted_cmd = format!("\"{}\"", exe_path.to_string_lossy());
        let data_wide: Vec<u16> = OsStr::new(&quoted_cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let byte_len = (data_wide.len() * 2) as u32;

        let set_rc = unsafe {
            RegSetValueExW(
                hkey,
                val_name_wide.as_ptr(),
                0,
                REG_SZ,
                data_wide.as_ptr() as *const u8,
                byte_len,
            )
        };
        unsafe {
            RegCloseKey(hkey);
        }

        if set_rc != 0 {
            return Err(format!("写入开机启动项失败 (Win32 Error: {})", set_rc));
        }
        Ok(())
    } else {
        let mut hkey: HKEY = ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        if rc != 0 || hkey.is_null() {
            return Err(format!("访问 HKCU Run 注册表项失败 (Win32 Error: {})", rc));
        }

        let del_rc = unsafe { RegDeleteValueW(hkey, val_name_wide.as_ptr()) };
        unsafe {
            RegCloseKey(hkey);
        }

        if del_rc != 0 && del_rc != ERROR_FILE_NOT_FOUND {
            return Err(format!("移除开机启动项失败 (Win32 Error: {})", del_rc));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub fn is_windows_hkcu_run_registered(value_name: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_SZ,
    };

    let subkey: Vec<u16> = OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_name_wide: Vec<u16> = OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if rc != 0 || hkey.is_null() {
        return false;
    }

    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 0;
    let q_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_name_wide.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            ptr::null_mut(),
            &mut byte_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }

    q_rc == 0 && val_type == REG_SZ && byte_len > 2
}

/// 在 Windows 当前用户注册表下确保 AppUserModelId 存在，使免安装 Portable.exe 也能稳定弹出原生系统通知
#[cfg(windows)]
pub fn ensure_windows_notification_aumid(aumid: &str, display_name: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let key_path = format!(r"Software\Classes\AppUserModelId\{}", aumid);
    let subkey: Vec<u16> = OsStr::new(&key_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_name: Vec<u16> = OsStr::new("DisplayName")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let data: Vec<u16> = OsStr::new(display_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = ptr::null_mut();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut hkey,
            ptr::null_mut(),
        )
    };
    if rc == 0 && !hkey.is_null() {
        unsafe {
            let _ = RegSetValueExW(
                hkey,
                val_name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            );
            RegCloseKey(hkey);
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| {
        h.join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", MACOS_LAUNCH_AGENT_LABEL))
    })
}

#[cfg(target_os = "macos")]
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn apply_macos_launch_agent(enabled: bool, exe_path: &Path) -> Result<(), String> {
    let plist_path = macos_plist_path().ok_or_else(|| "无法定位用户主目录".to_string())?;

    if enabled {
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("创建 LaunchAgents 目录失败: {}", e))?;
        }
        let escaped_exe = xml_escape(&exe_path.to_string_lossy());
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
            label = MACOS_LAUNCH_AGENT_LABEL,
            exe = escaped_exe
        );
        std::fs::write(&plist_path, content)
            .map_err(|e| format!("写入 macOS LaunchAgent 启动项失败: {}", e))?;
        Ok(())
    } else {
        if plist_path.exists() {
            std::fs::remove_file(&plist_path)
                .map_err(|e| format!("移除 macOS LaunchAgent 启动项失败: {}", e))?;
        }
        Ok(())
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn linux_autostart_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|c| c.join("autostart").join("claude-safe-lite.desktop"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn apply_linux_desktop_autostart(enabled: bool, exe_path: &Path) -> Result<(), String> {
    let desktop_path = linux_autostart_path().ok_or_else(|| "无法定位配置目录".to_string())?;
    if enabled {
        if let Some(parent) = desktop_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=Claude Safe Lite\nExec=\"{}\"\nTerminal=false\n",
            exe_path.to_string_lossy()
        );
        std::fs::write(&desktop_path, content).map_err(|e| e.to_string())?;
    } else if desktop_path.exists() {
        std::fs::remove_file(&desktop_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}
