//! 扩展工具启动器（Claude Code CLI / Claude 桌面端）、安全重置与跨平台系统对话框辅助（ToolLauncher）
//!
//! 严格遵循需求文档 5.5 / 5.6 / 5.7 / 0.6（兼容 Windows 与 macOS 双端）：
//! - 严禁不安全拼接命令行字符串，优先通过 `Command::arg()` 与 `Command::env()` 传参；
//! - 路径全程兼容含中文、空格与特殊符号的用户目录。

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::browser_launcher::BrowserLauncher;
use crate::forwarder::{ForwarderManager, LeaseOwner};
use crate::human_errors::HumanizedError;
use crate::logger::{LogKind, Logger};
use crate::proxy_store::{ProxyStore, ResolvedUpstreamProxy};

/// 「重置环境」多选参数（严格对应需求文档 5.5）
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetEnvOptions {
    pub clean_browser_profiles: bool,
    pub clean_logs: bool,
    pub clear_proxies: bool,
    pub restore_default_settings: bool,
}

/// 进程快照查询：判断指定进程映像名是否正在运行
pub fn is_process_running_by_name(proc_name: &str) -> bool {
    #[cfg(windows)]
    {
        use std::mem::{size_of, zeroed};
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let target_lower = proc_name.to_ascii_lowercase();
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return false;
        }

        let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let mut found = false;
        let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
        while ok != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = OsString::from_wide(&entry.szExeFile[..end])
                .to_string_lossy()
                .to_ascii_lowercase();
            if name == target_lower {
                found = true;
                break;
            }
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            ok = unsafe { Process32NextW(snap, &mut entry) };
        }

        unsafe {
            CloseHandle(snap);
        }
        found
    }

    #[cfg(unix)]
    {
        Command::new("/usr/bin/pgrep")
            .args(["-x", proc_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// 无黑框检测某个命令在系统 PATH 中是否可用
pub fn command_exists_in_path(binary_name: &str) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        Command::new("where.exe")
            .arg(binary_name)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(unix)]
    {
        Command::new("/usr/bin/which")
            .arg(binary_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// 探测本机 `claude` CLI 命令及可能需要补充进子进程 PATH 的目录
fn resolve_claude_cli_command() -> Option<(OsString, Option<PathBuf>)> {
    #[cfg(windows)]
    {
        if command_exists_in_path("claude") {
            let npm_dir = std::env::var_os("APPDATA")
                .map(|p| PathBuf::from(p).join("npm"))
                .filter(|d| d.is_dir());
            return Some((OsString::from("claude"), npm_dir));
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(appdata) = std::env::var_os("APPDATA") {
            candidates.push(PathBuf::from(&appdata).join("npm").join("claude.cmd"));
        }
        if let Some(home) = dirs::home_dir() {
            candidates.push(home.join(".local").join("bin").join("claude.exe"));
            candidates.push(home.join(".claude").join("local").join("claude.exe"));
        }

        for cand in candidates {
            if cand.is_file() {
                let parent = cand.parent().map(|p| p.to_path_buf());
                return Some((cand.into_os_string(), parent));
            }
        }

        None
    }

    #[cfg(unix)]
    {
        // macOS Finder 启动 GUI 应用时默认 PATH 不含 Homebrew / npm / nvm 目录，需主动扫描常见安装位置
        let mut candidates: Vec<PathBuf> = vec![
            PathBuf::from("/opt/homebrew/bin/claude"),
            PathBuf::from("/usr/local/bin/claude"),
        ];

        if let Some(home) = dirs::home_dir() {
            candidates.push(home.join(".local").join("bin").join("claude"));
            candidates.push(home.join(".claude").join("local").join("claude"));
            candidates.push(home.join(".npm-global").join("bin").join("claude"));

            // 探测 nvm 安装的最新版 Node 下的 claude
            let nvm_versions = home.join(".nvm").join("versions").join("node");
            if let Ok(entries) = fs::read_dir(&nvm_versions) {
                let mut node_bins: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path().join("bin").join("claude"))
                    .filter(|p| p.is_file())
                    .collect();
                node_bins.sort();
                node_bins.reverse();
                candidates.extend(node_bins);
            }
        }

        for cand in candidates {
            if cand.is_file() {
                let parent = cand.parent().map(|p| p.to_path_buf());
                return Some((cand.into_os_string(), parent));
            }
        }

        if command_exists_in_path("claude") {
            return Some((OsString::from("claude"), None));
        }

        None
    }
}

/// 为子进程注入本地转发器 HTTP/HTTPS 代理环境变量（同时覆盖大小写）
fn apply_proxy_env(cmd: &mut Command, proxy_env_val: &str, extra_path_dir: Option<&Path>) {
    cmd.env("HTTP_PROXY", proxy_env_val)
        .env("HTTPS_PROXY", proxy_env_val)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("http_proxy", proxy_env_val)
        .env("https_proxy", proxy_env_val)
        .env("no_proxy", "localhost,127.0.0.1");

    let path_sep = if cfg!(windows) { ";" } else { ":" };
    let mut path_parts: Vec<OsString> = Vec::new();
    if let Some(dir) = extra_path_dir {
        path_parts.push(OsString::from(dir.as_os_str()));
    }
    #[cfg(target_os = "macos")]
    {
        path_parts.push(OsString::from("/opt/homebrew/bin"));
        path_parts.push(OsString::from("/usr/local/bin"));
    }
    if let Some(existing) = std::env::var_os("PATH") {
        path_parts.push(existing);
    }
    if !path_parts.is_empty() {
        let mut joined = OsString::new();
        for (i, part) in path_parts.iter().enumerate() {
            if i > 0 {
                joined.push(path_sep);
            }
            joined.push(part);
        }
        cmd.env("PATH", joined);
    }
}

#[cfg(target_os = "macos")]
fn posix_single_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 启动 Claude Code (CLI) 独立终端并注入本地转发器 HTTP CONNECT 代理环境变量（需求文档 5.6）
pub async fn launch_claude_code_cli(
    workdir_opt: Option<String>,
    upstream: ResolvedUpstreamProxy,
    forwarder_mgr: &Arc<ForwarderManager>,
    logger: &Arc<Logger>,
) -> Result<String, HumanizedError> {
    let Some((cli_program, extra_path_dir)) = resolve_claude_cli_command() else {
        return Err(HumanizedError::new(
            "CLAUDE_CLI_NOT_FOUND",
            "未检测到 Claude Code (CLI) → 请先打开终端执行 npm install -g @anthropic-ai/claude-code 安装后再试",
            "claude CLI binary not found in PATH or standard npm/homebrew/nvm directories",
            Some(logger),
        ));
    };

    let workdir: PathBuf = match workdir_opt {
        Some(ref s) if !s.trim().is_empty() => {
            let p = PathBuf::from(s.trim());
            if !p.exists() || !p.is_dir() {
                return Err(HumanizedError::new(
                    "INVALID_WORKDIR",
                    "指定的工作目录不存在 → 请重新选择有效的文件夹路径",
                    format!("Workdir does not exist: {:?}", p),
                    Some(logger),
                ));
            }
            p
        }
        _ => dirs::home_dir().unwrap_or_else(std::env::temp_dir),
    };

    let lease = forwarder_mgr
        .acquire_lease(upstream.clone(), LeaseOwner::ClaudeCodeCli)
        .await?;
    let port = lease.port();
    let proxy_env_val = format!("http://127.0.0.1:{}", port);

    #[cfg(windows)]
    let (mut child, term_label, is_detached_launcher) = {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

        // 优先尝试 Windows Terminal；若 wt.exe 出现商店许可证失效 (-1058406399) 等错误，自动回退至系统 CMD 独立终端
        let mut used_wt = false;
        let mut wt_spawned = None;

        if command_exists_in_path("wt.exe") {
            let mut wt_cmd = Command::new("wt.exe");
            wt_cmd
                .arg("-d")
                .arg(&workdir)
                .arg("cmd.exe")
                .arg("/k")
                .arg(&cli_program);
            apply_proxy_env(&mut wt_cmd, &proxy_env_val, extra_path_dir.as_deref());

            match wt_cmd.spawn() {
                Ok(c) => {
                    used_wt = true;
                    wt_spawned = Some(c);
                }
                Err(wt_err) => {
                    logger.info(
                        LogKind::Launch,
                        format!(
                            "Windows Terminal (wt.exe) 启动不可用 ({})，已自动回退至系统 CMD 终端",
                            wt_err
                        ),
                    );
                }
            }
        }

        let spawned = match wt_spawned {
            Some(c) => c,
            None => {
                let mut cmd_fallback = Command::new("cmd.exe");
                cmd_fallback
                    .current_dir(&workdir)
                    .creation_flags(CREATE_NEW_CONSOLE)
                    .arg("/k")
                    .arg(&cli_program);
                apply_proxy_env(&mut cmd_fallback, &proxy_env_val, extra_path_dir.as_deref());

                cmd_fallback.spawn().map_err(|e| {
                    HumanizedError::new(
                        "CLI_SPAWN_FAILED",
                        "拉起系统终端失败 → 请检查系统 cmd.exe 组件是否正常",
                        e.to_string(),
                        Some(logger),
                    )
                })?
            }
        };

        let label = if used_wt { "Windows Terminal" } else { "CMD 终端" };
        (spawned, label, used_wt)
    };

    #[cfg(target_os = "macos")]
    let (mut child, term_label, is_detached_launcher) = {
        let mut path_prefix = String::from("/opt/homebrew/bin:/usr/local/bin:$PATH");
        if let Some(ref extra) = extra_path_dir {
            path_prefix = format!("{}:{}", extra.to_string_lossy(), path_prefix);
        }

        let shell_line = format!(
            "cd {} && export PATH=\"{}\" HTTP_PROXY={} HTTPS_PROXY={} http_proxy={} https_proxy={} ALL_PROXY='socks5h://127.0.0.1:{}' NO_PROXY='localhost,127.0.0.1' && clear && {}",
            posix_single_quote(&workdir.to_string_lossy()),
            path_prefix.replace('"', "\\\""),
            posix_single_quote(&proxy_env_val),
            posix_single_quote(&proxy_env_val),
            posix_single_quote(&proxy_env_val),
            posix_single_quote(&proxy_env_val),
            port,
            posix_single_quote(&cli_program.to_string_lossy()),
        );

        let apple_script = format!(
            "tell application \"Terminal\"\nactivate\ndo script \"{}\"\nend tell",
            applescript_escape(&shell_line)
        );

        let spawned = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&apple_script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                HumanizedError::new(
                    "CLI_SPAWN_FAILED",
                    "唤起 macOS 终端 (Terminal.app) 失败 → 请在系统设置「隐私与安全性 -> 自动化」中允许控制终端",
                    e.to_string(),
                    Some(logger),
                )
            })?;

        (spawned, "macOS Terminal", true)
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let (mut child, term_label, is_detached_launcher) = {
        let mut cmd = Command::new("x-terminal-emulator");
        cmd.current_dir(&workdir).arg("-e").arg(&cli_program);
        apply_proxy_env(&mut cmd, &proxy_env_val, extra_path_dir.as_deref());
        let spawned = cmd.spawn().map_err(|e| {
            HumanizedError::new(
                "CLI_SPAWN_FAILED",
                "拉起系统终端失败",
                e.to_string(),
                Some(logger),
            )
        })?;
        (spawned, "系统终端", false)
    };

    logger.info(
        LogKind::Launch,
        format!(
            "已启动 Claude Code (CLI) [{}] | 工作目录={:?} | 注入代理={}",
            term_label, workdir, proxy_env_val
        ),
    );

    // 后台守护租约：终端退出后尽力释放 Forwarder 引用
    let logger_bg = logger.clone();
    tokio::spawn(async move {
        let spawn_time = Instant::now();
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;

        // 若 wt.exe / osascript 作为 Launcher 在 2 秒内立即移交退出，则维持租约并在终端空闲或进程退出后自动回收
        if is_detached_launcher && spawn_time.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut idle_ticks = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let cli_alive = if cfg!(unix) {
                    is_process_running_by_name("claude")
                } else {
                    false
                };
                if lease.core().active_connections() == 0 && !cli_alive {
                    idle_ticks += 1;
                    if idle_ticks >= 6 {
                        break;
                    }
                } else {
                    idle_ticks = 0;
                }
            }
        }

        logger_bg.info(LogKind::Launch, "Claude Code 终端会话结束，已释放转发器引用");
        drop(lease);
    });

    Ok(format!(
        "已在 {} 启动 Claude Code（代理端口 127.0.0.1:{}）",
        term_label, port
    ))
}

/// 探测 `%LOCALAPPDATA%\AnthropicClaude\app-*\claude.exe` 最新语义版本路径（Windows Squirrel 安装版）
pub fn find_latest_claude_desktop_exe() -> Option<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")?;
    let base_dir = PathBuf::from(local_app_data).join("AnthropicClaude");
    let entries = fs::read_dir(&base_dir).ok()?;

    let mut candidates: Vec<((u64, u64, u64), PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if let Some(ver_part) = name_str.strip_prefix("app-") {
            let exe_path = entry.path().join("claude.exe");
            let exe_alt = entry.path().join("Claude.exe");
            let found_exe = if exe_path.is_file() {
                Some(exe_path)
            } else if exe_alt.is_file() {
                Some(exe_alt)
            } else {
                None
            };
            if let Some(p) = found_exe {
                candidates.push((parse_semver_tuple(ver_part), p));
            }
        }
    }

    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.into_iter().next().map(|(_, p)| p)
}

fn parse_semver_tuple(ver: &str) -> (u64, u64, u64) {
    let mut nums = ver
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u64>().ok());
    (
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
    )
}

/// 探测本机安装的 Claude 官方桌面客户端可执行入口（兼容 Windows 各版本与 macOS `/Applications/Claude.app`）
fn find_claude_desktop_launcher() -> Option<(PathBuf, &'static str)> {
    #[cfg(windows)]
    {
        if let Some(squirrel_exe) = find_latest_claude_desktop_exe() {
            return Some((squirrel_exe, "独立安装版"));
        }

        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let local_dir = PathBuf::from(&local_app_data);

            for rel in [
                &["Programs", "Claude", "Claude.exe"][..],
                &["Programs", "AnthropicClaude", "Claude.exe"][..],
                &["Claude", "Claude.exe"][..],
            ] {
                let mut p = local_dir.clone();
                for seg in rel {
                    p.push(seg);
                }
                if p.is_file() {
                    return Some((p, "桌面安装版"));
                }
            }

            let win_apps = local_dir.join("Microsoft").join("WindowsApps");
            for alias_name in ["claude-desktop.exe", "Claude.exe", "claude.exe"] {
                let alias_path = win_apps.join(alias_name);
                if fs::symlink_metadata(&alias_path).is_ok() {
                    return Some((alias_path, "MSIX 桌面版"));
                }
            }

            if let Ok(entries) = fs::read_dir(&win_apps) {
                for entry in entries.flatten() {
                    let name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if (name_lower == "claude-desktop.exe" || name_lower == "claude.exe")
                        && !name_lower.contains("ssh")
                        && !name_lower.contains("folder")
                    {
                        return Some((entry.path(), "MSIX 桌面版"));
                    }
                }
            }
        }

        if command_exists_in_path("claude-desktop.exe") {
            return Some((PathBuf::from("claude-desktop.exe"), "MSIX 桌面版"));
        }

        None
    }

    #[cfg(target_os = "macos")]
    {
        let mut candidates = vec![PathBuf::from("/Applications/Claude.app/Contents/MacOS/Claude")];
        if let Some(home) = dirs::home_dir() {
            candidates.push(home.join("Applications/Claude.app/Contents/MacOS/Claude"));
        }
        for cand in candidates {
            if cand.is_file() {
                return Some((cand, "macOS 官方版"));
            }
        }
        None
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        None
    }
}

/// 启动 Claude 桌面客户端（自动注入安全代理转发参数）
pub async fn launch_claude_desktop_app(
    upstream: ResolvedUpstreamProxy,
    forwarder_mgr: &Arc<ForwarderManager>,
    logger: &Arc<Logger>,
) -> Result<String, HumanizedError> {
    let already_running = if cfg!(windows) {
        is_process_running_by_name("claude.exe") || is_process_running_by_name("claude-desktop.exe")
    } else {
        is_process_running_by_name("Claude")
    };

    if already_running {
        let quit_hint = if cfg!(target_os = "macos") {
            "Claude 桌面端已在运行，请先彻底退出（按 Cmd+Q 关闭 Claude）后再通过本工具启动，以确保代理参数生效"
        } else {
            "Claude 桌面端已在运行，请先彻底退出（含右下角系统托盘图标）后再通过本工具启动，以确保代理参数生效"
        };
        return Err(HumanizedError::new(
            "CLAUDE_DESKTOP_ALREADY_RUNNING",
            quit_hint,
            "Claude Desktop process is already active",
            Some(logger),
        ));
    }

    let Some((exe_path, variant_label)) = find_claude_desktop_launcher() else {
        return Err(HumanizedError::new(
            "CLAUDE_DESKTOP_NOT_FOUND",
            "未检测到 Claude 桌面客户端 → 请先安装官方桌面版，或直接使用左侧【启动安全浏览器】安全访问 Claude",
            "Claude desktop executable not found in standard installation paths",
            Some(logger),
        ));
    };

    let lease = forwarder_mgr
        .acquire_lease(upstream, LeaseOwner::ClaudeDesktop)
        .await?;
    let port = lease.port();
    let http_proxy_env = format!("http://127.0.0.1:{}", port);

    let mut cmd = Command::new(&exe_path);
    cmd.arg(format!("--proxy-server=socks5://127.0.0.1:{}", port))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_proxy_env(&mut cmd, &http_proxy_env, None);

    let mut child = cmd.spawn().map_err(|e| {
        let user_msg = if e.raw_os_error() == Some(-1058406399) {
            "Claude 桌面客户端微软商店应用许可证无效 (0xC0EA0001) → 请从 Anthropic 官网重新安装桌面版，或改用【启动安全浏览器】"
        } else {
            "启动 Claude 桌面客户端失败 → 请检查桌面客户端安装是否完整，或改用【启动安全浏览器】"
        };
        HumanizedError::new(
            "CLAUDE_DESKTOP_SPAWN_FAILED",
            user_msg,
            e.to_string(),
            Some(logger),
        )
    })?;

    logger.info(
        LogKind::Launch,
        format!(
            "已启动 Claude 桌面端 [{}] ({:?}) | 本地代理=socks5://127.0.0.1:{}",
            variant_label, exe_path, port
        ),
    );

    let logger_bg = logger.clone();
    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
        let proc_watch_name = if cfg!(windows) { "claude.exe" } else { "Claude" };
        for _ in 0..6 {
            if is_process_running_by_name(proc_watch_name) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        while is_process_running_by_name(proc_watch_name) {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        logger_bg.info(LogKind::Launch, "Claude 桌面端已退出，释放本地转发器引用");
        drop(lease);
    });

    Ok(format!(
        "已通过安全代理 (127.0.0.1:{}) 启动 Claude 桌面端（{}）",
        port, variant_label
    ))
}

/// 执行「重置环境」（需求文档 5.5：运行中拦截 + 按勾选项安全清理）
pub fn execute_reset_environment(
    options: &ResetEnvOptions,
    browser_launcher: &BrowserLauncher,
    proxy_store: &ProxyStore,
    logger: &Logger,
) -> Result<ResetSummary, HumanizedError> {
    if browser_launcher.is_running() {
        return Err(HumanizedError::new(
            "RESET_BLOCKED_BROWSER_RUNNING",
            "安全浏览器正在运行中 → 请先关闭安全浏览器后再执行环境重置",
            "BrowserLauncher::is_running() == true",
            Some(logger),
        ));
    }

    let mut cleaned_items: Vec<&'static str> = Vec::new();

    if options.clean_browser_profiles {
        let profiles_dir = proxy_store.profiles_dir();
        if profiles_dir.exists() {
            fs::remove_dir_all(&profiles_dir).map_err(|e| {
                HumanizedError::new(
                    "CLEAN_PROFILES_FAILED",
                    "清理浏览器配置目录失败（可能有残留进程占用文件） → 请确认浏览器已彻底退出后重试",
                    e.to_string(),
                    Some(logger),
                )
            })?;
        }
        let _ = fs::create_dir_all(&profiles_dir);
        cleaned_items.push("全部浏览器隔离目录");
    }

    if options.clean_logs {
        logger.clear_all().map_err(|e| {
            HumanizedError::new(
                "CLEAN_LOGS_FAILED",
                "清空历史日志文件失败",
                e.to_string(),
                Some(logger),
            )
        })?;
        cleaned_items.push("全部历史日志");
    }

    if options.clear_proxies || options.restore_default_settings {
        proxy_store
            .reset_store(options.clear_proxies, options.restore_default_settings)
            .map_err(|e| {
                HumanizedError::new(
                    "RESET_STORE_FAILED",
                    "重置配置文件失败",
                    e.to_string(),
                    Some(logger),
                )
            })?;
        if options.clear_proxies {
            cleaned_items.push("全部代理配置");
        }
        if options.restore_default_settings {
            cleaned_items.push("应用默认设置");
        }
    }

    let summary_text = if cleaned_items.is_empty() {
        "未勾选任何重置项".to_string()
    } else {
        format!("已完成环境重置：{}", cleaned_items.join("、"))
    };

    logger.info(LogKind::App, &summary_text);
    Ok(ResetSummary {
        message: summary_text,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetSummary {
    pub message: String,
}

/// 安全调用系统默认浏览器打开外部 `https://` 链接（例如 Brave 官方下载页）
pub fn open_external_https_url(raw_url: &str, logger: &Logger) -> Result<(), HumanizedError> {
    let trimmed = raw_url.trim();
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        HumanizedError::new("INVALID_URL", "链接地址格式无效", e.to_string(), Some(logger))
    })?;

    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(HumanizedError::new(
            "DISALLOWED_URL_SCHEME",
            "出于安全限制，仅允许打开 HTTP/HTTPS 网页链接",
            format!("Blocked scheme: {}", parsed.scheme()),
            Some(logger),
        ));
    }

    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let verb: Vec<u16> = OsStr::new("open")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target: Vec<u16> = OsStr::new(parsed.as_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let code = unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                verb.as_ptr(),
                target.as_ptr(),
                ptr::null(),
                ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize;

        if code <= 32 {
            return Err(HumanizedError::new(
                "SHELL_OPEN_FAILED",
                "无法调用系统默认浏览器打开链接，请手动复制网址访问",
                format!("ShellExecuteW returned code {}", code),
                Some(logger),
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/usr/bin/open")
            .arg(parsed.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                HumanizedError::new(
                    "SHELL_OPEN_FAILED",
                    "无法调用系统默认浏览器打开链接，请手动复制网址访问",
                    e.to_string(),
                    Some(logger),
                )
            })?;
        if !status.success() {
            return Err(HumanizedError::new(
                "SHELL_OPEN_FAILED",
                "无法调用系统默认浏览器打开链接，请手动复制网址访问",
                format!("open exited with {}", status),
                Some(logger),
            ));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("xdg-open")
            .arg(parsed.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }

    Ok(())
}

/// 调用系统原生「另存为」对话框选择日志导出目标路径
pub fn show_save_log_dialog(default_file_name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::mem::{size_of, zeroed};
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetSaveFileNameW, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
        };

        let mut file_buf: Vec<u16> = vec![0u16; 1024];
        for (idx, unit) in OsStr::new(default_file_name).encode_wide().enumerate() {
            if idx + 1 < file_buf.len() {
                file_buf[idx] = unit;
            }
        }

        let filter_str = "日志文件 (*.log;*.txt)\0*.log;*.txt\0所有文件 (*.*)\0*.*\0\0";
        let filter_wide: Vec<u16> = filter_str.encode_utf16().collect();
        let def_ext: Vec<u16> = "log\0".encode_utf16().collect();
        let title: Vec<u16> = "导出脱敏日志文件\0".encode_utf16().collect();

        let mut ofn: OPENFILENAMEW = unsafe { zeroed() };
        ofn.lStructSize = size_of::<OPENFILENAMEW>() as u32;
        ofn.lpstrFilter = filter_wide.as_ptr();
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = file_buf.len() as u32;
        ofn.lpstrTitle = title.as_ptr();
        ofn.lpstrDefExt = def_ext.as_ptr();
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

        let accepted = unsafe { GetSaveFileNameW(&mut ofn) };
        if accepted == 0 {
            return None;
        }

        let len = file_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(file_buf.len());
        if len == 0 {
            None
        } else {
            Some(PathBuf::from(OsString::from_wide(&file_buf[..len])))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "POSIX path of (choose file name with prompt \"导出脱敏日志文件\" default name \"{}\")",
            applescript_escape(default_file_name)
        );
        let out = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let chosen = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if chosen.is_empty() {
            None
        } else {
            Some(PathBuf::from(chosen))
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        dirs::download_dir().map(|d| d.join(default_file_name))
    }
}

/// 检查路径辅助（供测试调用）
pub fn is_valid_dir(p: &Path) -> bool {
    p.exists() && p.is_dir()
}
