//! 安全浏览器探测、防泄露参数注入与跨平台进程树隔离管控模块（BrowserLauncher）
//!
//! 核心安全机制（需求文档 4.2 + macOS 跨平台原生扩展）：
//! 1. 探测优先级：手动指定路径（macOS 支持直接指定 `.app` 应用包或内部二进制） → Brave → Chrome（完全不含 Edge/Safari）；
//! 2. 路径与参数安全：全程使用 `PathBuf` / `OsString` 与 `Command::arg()`，严禁手动拼接命令行字符串；
//! 3. 零逃逸进程树隔离与精准强杀：
//!    - Windows：`CREATE_SUSPENDED` 挂起态创建子进程 → 绑定设置了 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的 Win32 `Job Object` → 恢复主线程；
//!      熔断或关闭时调用 `TerminateJobObject` 毫秒级强杀全部子进程；
//!    - macOS / Unix：`process_group(0)` 创建独立进程组（PGID 隔离），结合 `try_wait` 防僵尸进程 + `kill(-pgid, 0)` + `SingletonLock` 监测存活；
//!      熔断或关闭时调用 `kill(-pgid, SIGKILL)` 毫秒级强杀整个进程组，100% 不误杀用户自己打开的普通浏览器窗口。

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Child;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::constants::CLAUDE_WEB_URL;
use crate::forwarder::ForwarderLease;
use crate::human_errors::HumanizedError;
use crate::logger::{LogKind, Logger};

/// 浏览器类型标识
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserKind {
    Custom,
    Brave,
    Chrome,
}

impl BrowserKind {
    pub fn display_name(self) -> &'static str {
        match self {
            BrowserKind::Custom => "自定义浏览器",
            BrowserKind::Brave => "Brave",
            BrowserKind::Chrome => "Google Chrome",
        }
    }
}

/// 探测到的可用浏览器可执行文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedBrowser {
    pub kind: BrowserKind,
    pub path: PathBuf,
}

/// 推送给前端的浏览器运行状态（对齐需求文档 8.3 `browser-state`）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserLifecycleState {
    Idle,
    Launching,
    Running,
    Exited,
}

// ============================================================================
// Windows 平台进程树隔离沙箱：Win32 Job Object
// ============================================================================
#[cfg(windows)]
mod win_job {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenThread, ResumeThread, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
    };

    /// 独占管控一个子进程树的 Win32 Job Object 句柄封装
    pub struct Win32ProcessJob {
        handle: HANDLE,
    }

    // SAFETY: Win32 Job Object 内核句柄是进程级线程安全的内核对象，跨线程查询与终止均受操作系统保护
    unsafe impl Send for Win32ProcessJob {}
    unsafe impl Sync for Win32ProcessJob {}

    impl Win32ProcessJob {
        /// 创建一个配置了 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的全新匿名 Job Object
        pub fn create() -> Result<Self, String> {
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle.is_null() {
                let err = unsafe { GetLastError() };
                return Err(format!("CreateJobObjectW 失败 (Win32 Error: {})", err));
            }

            let mut ext_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            ext_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &ext_info as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };

            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                return Err(format!(
                    "SetInformationJobObject(KILL_ON_JOB_CLOSE) 失败 (Win32 Error: {})",
                    err
                ));
            }

            Ok(Self { handle })
        }

        /// 以 `CREATE_SUSPENDED` 零竞态方式启动 `Command`、将其绑定进当前 Job Object 后再恢复主线程执行。
        /// 若绑定失败，立即终止挂起态进程（Fail-Closed），绝不允许脱离管控运行。
        pub fn spawn_command_in_job(
            &self,
            cmd: &mut Command,
            extra_creation_flags: u32,
        ) -> Result<Child, String> {
            cmd.creation_flags(extra_creation_flags | CREATE_SUSPENDED);
            let mut child = cmd
                .spawn()
                .map_err(|e| format!("启动子进程失败: {}", e))?;

            let raw_proc_handle = child.as_raw_handle() as HANDLE;
            let assign_ok = unsafe { AssignProcessToJobObject(self.handle, raw_proc_handle) };
            if assign_ok == 0 {
                let err = unsafe { GetLastError() };
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "AssignProcessToJobObject 失败 (Win32 Error: {})",
                    err
                ));
            }

            if let Err(resume_err) = resume_all_threads_of_process(child.id()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(resume_err);
            }

            Ok(child)
        }

        /// 查询当前 Job Object 内活跃存活的进程总数（包含子孙进程）
        pub fn active_process_count(&self) -> u32 {
            if self.handle.is_null() {
                return 0;
            }
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            let ok = unsafe {
                QueryInformationJobObject(
                    self.handle,
                    JobObjectBasicAccountingInformation,
                    &mut info as *mut _ as *mut _,
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                0
            } else {
                info.ActiveProcesses
            }
        }

        /// 立即强制终止该 Job Object 内的全部父子进程树
        pub fn terminate_all(&mut self, exit_code: u32) {
            if !self.handle.is_null() {
                unsafe {
                    let _ = TerminateJobObject(self.handle, exit_code);
                    let _ = CloseHandle(self.handle);
                }
                self.handle = ptr::null_mut();
            }
        }
    }

    impl Drop for Win32ProcessJob {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    let _ = TerminateJobObject(self.handle, 1);
                    let _ = CloseHandle(self.handle);
                }
                self.handle = ptr::null_mut();
            }
        }
    }

    fn resume_all_threads_of_process(pid: u32) -> Result<(), String> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "CreateToolhelp32Snapshot(SNAPTHREAD) 失败 (Win32 Error: {})",
                err
            ));
        }

        let mut entry: THREADENTRY32 = unsafe { zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;

        let mut resumed_any = false;
        let mut has_item = unsafe { Thread32First(snap, &mut entry) };
        while has_item != 0 {
            if entry.th32OwnerProcessID == pid {
                let h_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if !h_thread.is_null() {
                    let prev = unsafe { ResumeThread(h_thread) };
                    unsafe {
                        CloseHandle(h_thread);
                    }
                    if prev != u32::MAX {
                        resumed_any = true;
                    }
                }
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            has_item = unsafe { Thread32Next(snap, &mut entry) };
        }

        unsafe {
            CloseHandle(snap);
        }

        if !resumed_any {
            return Err(format!("未能找到并恢复子进程 (PID={}) 的挂起主线程", pid));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use win_job::Win32ProcessJob;

// ============================================================================
// macOS / Unix 平台进程树隔离沙箱：独立进程组 (Process Group, PGID)
// ============================================================================
#[cfg(unix)]
pub struct UnixProcessGroup {
    pgid: Option<i32>,
    root_child: Mutex<Option<Child>>,
}

#[cfg(unix)]
impl UnixProcessGroup {
    pub fn create() -> Result<Self, String> {
        Ok(Self {
            pgid: None,
            root_child: Mutex::new(None),
        })
    }

    /// 以 `process_group(0)` 启动独立进程组，确保该安全浏览器的全部子孙进程归属同一专属 PGID
    pub fn spawn_command_in_group(&mut self, cmd: &mut Command) -> Result<u32, String> {
        use std::os::unix::process::CommandExt;

        cmd.process_group(0);
        let child = cmd
            .spawn()
            .map_err(|e| format!("启动安全浏览器子进程失败: {}", e))?;
        let pid = child.id();
        self.pgid = Some(pid as i32);
        if let Ok(mut guard) = self.root_child.lock() {
            *guard = Some(child);
        }
        Ok(pid)
    }

    /// 检测专属进程组内是否仍有活跃进程（先回收可能已退出的根子进程以消除僵尸态 `<defunct>`）
    pub fn has_active_processes(&self) -> bool {
        let Some(pgid) = self.pgid else {
            return false;
        };
        if pgid <= 1 {
            return false;
        }

        if let Ok(mut guard) = self.root_child.lock() {
            if let Some(ref mut child) = *guard {
                if let Ok(Some(_)) = child.try_wait() {
                    *guard = None;
                }
            }
        }

        // 向负 PGID 发送信号 0：若组内存在至少一个未回收进程，返回 0；若组内进程全部退出，返回 -1 (ESRCH)
        let rc = unsafe { libc::kill(-pgid, 0) };
        if rc == 0 {
            true
        } else {
            let err = std::io::Error::last_os_error();
            err.raw_os_error() == Some(libc::EPERM)
        }
    }

    /// 立即向整个专属进程组发送 `SIGKILL` 强制终止全部父子进程，绝不波及用户普通浏览器
    pub fn terminate_all(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            if pgid > 1 {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
        }
        if let Ok(mut guard) = self.root_child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[cfg(unix)]
impl Drop for UnixProcessGroup {
    fn drop(&mut self) {
        self.terminate_all();
    }
}

// 统一跨平台进程沙箱内部抽象
enum PlatformSandbox {
    #[cfg(windows)]
    WinJob(Win32ProcessJob),
    #[cfg(unix)]
    UnixPgrp(UnixProcessGroup),
}

impl PlatformSandbox {
    fn create_and_spawn(cmd: &mut Command) -> Result<(Self, u32), String> {
        #[cfg(windows)]
        {
            let job = Win32ProcessJob::create()?;
            let child = job.spawn_command_in_job(cmd, 0)?;
            let pid = child.id();
            drop(child); // 句柄已由 Win32 Job Object 内核级托管
            Ok((Self::WinJob(job), pid))
        }

        #[cfg(unix)]
        {
            let mut pgrp = UnixProcessGroup::create()?;
            let pid = pgrp.spawn_command_in_group(cmd)?;
            Ok((Self::UnixPgrp(pgrp), pid))
        }
    }

    fn is_alive(&self) -> bool {
        match self {
            #[cfg(windows)]
            Self::WinJob(job) => job.active_process_count() > 0,
            #[cfg(unix)]
            Self::UnixPgrp(pgrp) => pgrp.has_active_processes(),
        }
    }

    fn terminate_all(&mut self) {
        match self {
            #[cfg(windows)]
            Self::WinJob(job) => job.terminate_all(1),
            #[cfg(unix)]
            Self::UnixPgrp(pgrp) => pgrp.terminate_all(),
        }
    }
}

// ============================================================================
// 跨平台浏览器路径解析与探测（手动路径 → Brave → Chrome，完全不含 Edge / Safari）
// ============================================================================

/// 解析浏览器可执行文件真实路径：
/// - 若传入本身是普通文件，直接返回；
/// - 在 macOS 下，若传入的是 `/Applications/Brave Browser.app` 这类 `.app` 应用包目录，
///   自动定位其 `Contents/MacOS/` 下的真实可执行二进制。
pub fn resolve_browser_executable_path(raw_path: &Path) -> Option<PathBuf> {
    if raw_path.exists() && raw_path.is_file() {
        return Some(raw_path.to_path_buf());
    }

    #[cfg(target_os = "macos")]
    {
        let is_app_bundle = raw_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("app"))
            .unwrap_or(false);

        if is_app_bundle && raw_path.is_dir() {
            let macos_bin_dir = raw_path.join("Contents").join("MacOS");
            if macos_bin_dir.is_dir() {
                for preferred in ["Brave Browser", "Google Chrome", "Chromium"] {
                    let cand = macos_bin_dir.join(preferred);
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
                if let Ok(entries) = fs::read_dir(&macos_bin_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }

    None
}

/// 按「手动指定路径 → Brave → Chrome」顺序探测可用浏览器可执行文件
pub fn detect_browser(
    custom_path: Option<&str>,
    logger: Option<&Logger>,
) -> Result<DetectedBrowser, HumanizedError> {
    if let Some(raw_custom) = custom_path {
        let trimmed = raw_custom.trim().trim_matches('"');
        if !trimmed.is_empty() {
            let pb = PathBuf::from(trimmed);
            if let Some(resolved) = resolve_browser_executable_path(&pb) {
                return Ok(DetectedBrowser {
                    kind: BrowserKind::Custom,
                    path: resolved,
                });
            }
            return Err(HumanizedError::new(
                "CUSTOM_BROWSER_INVALID",
                "设置中手动指定的浏览器路径不存在 → 请在设置页重新选择有效浏览器（或清空以使用自动探测）",
                format!("Custom browser path not found: {}", trimmed),
                logger,
            ));
        }
    }

    #[cfg(windows)]
    {
        if let Some(brave_path) = probe_windows_browser_candidates(
            "brave.exe",
            &[
                ("ProgramFiles", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                ("ProgramFiles(x86)", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ],
        ) {
            return Ok(DetectedBrowser {
                kind: BrowserKind::Brave,
                path: brave_path,
            });
        }

        if let Some(chrome_path) = probe_windows_browser_candidates(
            "chrome.exe",
            &[
                ("ProgramFiles", r"Google\Chrome\Application\chrome.exe"),
                ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"),
                ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
            ],
        ) {
            return Ok(DetectedBrowser {
                kind: BrowserKind::Chrome,
                path: chrome_path,
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(brave_path) =
            probe_macos_app_bundle("Brave Browser.app", "Brave Browser", "com.brave.Browser")
        {
            return Ok(DetectedBrowser {
                kind: BrowserKind::Brave,
                path: brave_path,
            });
        }

        if let Some(chrome_path) =
            probe_macos_app_bundle("Google Chrome.app", "Google Chrome", "com.google.Chrome")
        {
            return Ok(DetectedBrowser {
                kind: BrowserKind::Chrome,
                path: chrome_path,
            });
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for (bin, kind) in [
            ("brave-browser", BrowserKind::Brave),
            ("brave", BrowserKind::Brave),
            ("google-chrome", BrowserKind::Chrome),
            ("chromium", BrowserKind::Chrome),
        ] {
            for dir in ["/usr/bin", "/usr/local/bin", "/snap/bin"] {
                let p = Path::new(dir).join(bin);
                if p.is_file() {
                    return Ok(DetectedBrowser { kind, path: p });
                }
            }
        }
    }

    Err(HumanizedError::browser_not_found())
}

#[cfg(target_os = "macos")]
fn probe_macos_app_bundle(
    app_folder_name: &str,
    binary_name: &str,
    bundle_id: &str,
) -> Option<PathBuf> {
    let mut app_dirs = vec![PathBuf::from("/Applications").join(app_folder_name)];
    if let Some(home) = dirs::home_dir() {
        app_dirs.push(home.join("Applications").join(app_folder_name));
    }

    for app_dir in app_dirs {
        let exe = app_dir.join("Contents").join("MacOS").join(binary_name);
        if exe.is_file() {
            return Some(exe);
        }
    }

    // Spotlight 兜底探测（兼容用户将 .app 放在外置盘或自定义文件夹的情况）
    if let Ok(out) = Command::new("/usr/bin/mdfind")
        .arg(format!("kMDItemCFBundleIdentifier == '{}'", bundle_id))
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let p = PathBuf::from(line.trim());
                if let Some(resolved) = resolve_browser_executable_path(&p) {
                    return Some(resolved);
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn probe_windows_browser_candidates(
    exe_name: &str,
    env_rel_paths: &[(&str, &str)],
) -> Option<PathBuf> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    // 1. 先查注册表 HKCU 与 HKLM 下的 App Paths
    let subkey = format!(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{}",
        exe_name
    );
    for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        if let Some(reg_path) = query_registry_default_path(root, &subkey) {
            if reg_path.exists() && reg_path.is_file() {
                return Some(reg_path);
            }
        }
    }

    // 2. 再查常见标准安装路径（全部用 OsString 拼接，兼容非 ASCII 用户目录）
    for (env_key, rel) in env_rel_paths {
        if let Some(base) = std::env::var_os(env_key) {
            let candidate = PathBuf::from(base).join(rel);
            if candidate.exists() && candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(windows)]
fn query_registry_default_path(
    root_hkey: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ, REG_EXPAND_SZ, REG_SZ,
    };

    let wide_subkey: Vec<u16> = OsStr::new(subkey)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut hkey: HKEY = ptr::null_mut();

    let open_status = unsafe {
        RegOpenKeyExW(
            root_hkey,
            wide_subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if open_status != 0 || hkey.is_null() {
        return None;
    }

    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 0;
    let query_size = unsafe {
        RegQueryValueExW(
            hkey,
            ptr::null(),
            ptr::null_mut(),
            &mut val_type,
            ptr::null_mut(),
            &mut byte_len,
        )
    };

    if query_size != 0 || byte_len == 0 || (val_type != REG_SZ && val_type != REG_EXPAND_SZ) {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let u16_len = (byte_len as usize).div_ceil(2) + 1;
    let mut buf: Vec<u16> = vec![0u16; u16_len];
    let mut actual_bytes = (buf.len() * 2) as u32;
    let query_ok = unsafe {
        RegQueryValueExW(
            hkey,
            ptr::null(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut actual_bytes,
        )
    };

    unsafe {
        RegCloseKey(hkey);
    }

    if query_ok != 0 {
        return None;
    }

    let end_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let raw_str = OsString::from_wide(&buf[..end_pos]);
    let cleaned = raw_str.to_string_lossy();
    let unquoted = cleaned.trim().trim_matches('"');
    if unquoted.is_empty() {
        None
    } else {
        Some(PathBuf::from(unquoted))
    }
}

/// 检查指定浏览器隔离配置目录是否正被活跃的 Chromium 浏览器进程锁定
pub fn is_profile_dir_locked(profile_dir: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let lockfile = profile_dir.join("lockfile");
        if !lockfile.exists() {
            return false;
        }
        // 尝试以独占无共享方式打开 lockfile：若返回 ERROR_SHARING_VIOLATION (32) 则说明浏览器正在运行占用它
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lockfile)
        {
            Ok(_) => false,
            Err(e) => {
                e.raw_os_error() == Some(32) || e.kind() == std::io::ErrorKind::PermissionDenied
            }
        }
    }

    #[cfg(unix)]
    {
        // Chromium 在 macOS / Linux 下创建指向 `<hostname>-<pid>` 的符号链接 `SingletonLock`
        let singleton_lock = profile_dir.join("SingletonLock");
        if let Ok(target) = fs::read_link(&singleton_lock) {
            let target_str = target.to_string_lossy();
            if let Some((_, pid_str)) = target_str.rsplit_once('-') {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if pid > 1 {
                        let rc = unsafe { libc::kill(pid, 0) };
                        if rc == 0
                            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

/// 构造安全浏览器全部防泄露命令行参数（返回 `Vec<OsString>` 供 `Command::args` 逐项安全传入）
pub fn build_hardened_browser_args(profile_dir: &Path, forwarder_port: u16) -> Vec<OsString> {
    let mut user_data_arg = OsString::from("--user-data-dir=");
    user_data_arg.push(profile_dir.as_os_str());

    vec![
        user_data_arg,
        OsString::from(format!("--proxy-server=socks5://127.0.0.1:{}", forwarder_port)),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from("--disable-quic"),
        OsString::from("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"),
        OsString::from("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"),
        OsString::from(CLAUDE_WEB_URL),
    ]
}

// ============================================================================
// 安全浏览器会话控制器（BrowserLauncher）
// ============================================================================

struct ActiveBrowserSession {
    session_id: u64,
    proxy_id: String,
    proxy_name: String,
    browser: DetectedBrowser,
    profile_dir: PathBuf,
    sandbox: PlatformSandbox,
    /// 持有本地 Forwarder 引用计数租约；会话销毁时自动 Drop 释放端口
    _forwarder_lease: ForwarderLease,
}

pub struct BrowserLauncher {
    logger: Arc<Logger>,
    active: Mutex<Option<ActiveBrowserSession>>,
    next_session_id: Mutex<u64>,
    state_listener: Mutex<Option<Arc<dyn Fn(BrowserLifecycleState) + Send + Sync>>>,
    natural_exit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl BrowserLauncher {
    pub fn new(logger: Arc<Logger>) -> Arc<Self> {
        Arc::new(Self {
            logger,
            active: Mutex::new(None),
            next_session_id: Mutex::new(1),
            state_listener: Mutex::new(None),
            natural_exit_hook: Mutex::new(None),
        })
    }

    pub fn set_state_listener<F>(&self, cb: F)
    where
        F: Fn(BrowserLifecycleState) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.state_listener.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    /// 注册浏览器自然退出时的联动回调（例如停止 Watchdog 巡检、更新托盘菜单）
    pub fn set_natural_exit_hook<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.natural_exit_hook.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    fn emit_state(&self, state: BrowserLifecycleState) {
        let cb = self
            .state_listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(f) = cb {
            f(state);
        }
    }

    pub fn is_running(&self) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    pub fn running_proxy_id(&self) -> Option<String> {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|s| s.proxy_id.clone())
    }

    pub fn running_browser(&self) -> Option<DetectedBrowser> {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|s| s.browser.clone())
    }

    /// 启动隔离安全浏览器并纳入系统级进程沙箱实时存活监控
    pub fn launch_isolated(
        self: &Arc<Self>,
        proxy_id: String,
        proxy_name: String,
        profile_dir: PathBuf,
        custom_browser_path: Option<&str>,
        forwarder_lease: ForwarderLease,
    ) -> Result<DetectedBrowser, HumanizedError> {
        // 1. 防重复启动拦截
        {
            let guard = self.active.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref existing) = *guard {
                if existing.proxy_id == proxy_id {
                    return Err(HumanizedError::profile_in_use(&proxy_name));
                }
                return Err(HumanizedError::new(
                    "BROWSER_ALREADY_RUNNING",
                    format!(
                        "已有安全浏览器正在运行（当前代理：{}），请先关闭后再启动新会话",
                        existing.proxy_name
                    ),
                    "Active safe browser session already exists",
                    Some(&self.logger),
                ));
            }
        }

        fs::create_dir_all(&profile_dir).map_err(|e| {
            HumanizedError::new(
                "PROFILE_DIR_ERROR",
                "创建浏览器隔离配置目录失败 → 请检查磁盘空间或目录权限",
                e.to_string(),
                Some(&self.logger),
            )
        })?;

        if is_profile_dir_locked(&profile_dir) {
            return Err(HumanizedError::profile_in_use(&proxy_name));
        }

        // 2. 探测浏览器路径
        let detected = detect_browser(custom_browser_path, Some(&self.logger))?;
        self.emit_state(BrowserLifecycleState::Launching);

        // 3. 在系统级隔离沙箱（Win32 Job Object / macOS Process Group）中启动浏览器
        let forwarder_port = forwarder_lease.port();
        let args = build_hardened_browser_args(&profile_dir, forwarder_port);
        let mut cmd = Command::new(&detected.path);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let (sandbox, root_pid) = PlatformSandbox::create_and_spawn(&mut cmd).map_err(|err_msg| {
            self.emit_state(BrowserLifecycleState::Idle);
            HumanizedError::new(
                "BROWSER_SPAWN_ERROR",
                "启动安全浏览器进程失败 → 请检查浏览器文件是否完整或系统安全权限设置",
                err_msg,
                Some(&self.logger),
            )
        })?;

        let session_id = {
            let mut id_guard = self
                .next_session_id
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let id = *id_guard;
            *id_guard += 1;
            id
        };

        self.logger.info(
            LogKind::Launch,
            format!(
                "已启动安全浏览器: {} ({:?}) | 初始PID={} | 代理={} | 本地转发端口=127.0.0.1:{}",
                detected.kind.display_name(),
                detected.path,
                root_pid,
                proxy_name,
                forwarder_port
            ),
        );

        {
            let mut guard = self.active.lock().unwrap_or_else(|p| p.into_inner());
            *guard = Some(ActiveBrowserSession {
                session_id,
                proxy_id,
                proxy_name,
                browser: detected.clone(),
                profile_dir: profile_dir.clone(),
                sandbox,
                _forwarder_lease: forwarder_lease,
            });
        }

        self.emit_state(BrowserLifecycleState::Running);

        // 4. 启动每秒一次的沙箱进程数 + 配置目录锁存活监控协程
        let launcher_clone = self.clone();
        tokio::spawn(async move {
            let launch_instant = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let still_alive = {
                    let guard = launcher_clone
                        .active
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let Some(ref sess) = *guard else {
                        return;
                    };
                    if sess.session_id != session_id {
                        return;
                    }

                    if sess.sandbox.is_alive() {
                        true
                    } else if launch_instant.elapsed() < Duration::from_secs(3) {
                        is_profile_dir_locked(&sess.profile_dir)
                    } else {
                        is_profile_dir_locked(&sess.profile_dir)
                    }
                };

                if !still_alive {
                    let removed = {
                        let mut guard = launcher_clone
                            .active
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        if guard.as_ref().map(|s| s.session_id) == Some(session_id) {
                            guard.take()
                        } else {
                            None
                        }
                    };

                    if let Some(sess) = removed {
                        launcher_clone.logger.info(
                            LogKind::Launch,
                            format!(
                                "检测到安全浏览器已退出 (代理: {})，自动释放本地转发端口",
                                sess.proxy_name
                            ),
                        );
                        drop(sess);
                        launcher_clone.emit_state(BrowserLifecycleState::Exited);
                        launcher_clone.emit_state(BrowserLifecycleState::Idle);

                        let hook = launcher_clone
                            .natural_exit_hook
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .clone();
                        if let Some(cb) = hook {
                            cb();
                        }
                    }
                    return;
                }
            }
        });

        Ok(detected)
    }

    /// 强制终止安全浏览器整个隔离进程树并立即释放 Forwarder 引用（供安全熔断或用户点击「关闭安全浏览器」调用）
    pub fn force_kill(&self, reason: &str) -> bool {
        let removed = {
            let mut guard = self.active.lock().unwrap_or_else(|p| p.into_inner());
            guard.take()
        };

        if let Some(mut sess) = removed {
            sess.sandbox.terminate_all();
            self.logger.info(
                LogKind::Launch,
                format!(
                    "已强制终止安全浏览器隔离进程树 (代理: {}，原因: {})",
                    sess.proxy_name, reason
                ),
            );
            drop(sess);
            self.emit_state(BrowserLifecycleState::Exited);
            self.emit_state(BrowserLifecycleState::Idle);
            true
        } else {
            false
        }
    }
}
