//! 跨平台系统版本探测与一键 `***` 强脱敏诊断报告生成模块（Diagnostics）
//!
//! 严格安全要求：
//! 1. 复制到剪贴板前，自动对节点密码、敏感代理地址（域名/IP）、出口 IP 以及完整授权码执行 `***` 脱敏；
//! 2. 同时兼容 Windows 10/11（准确区分 Build >= 22000 为 Windows 11）与 macOS 系统版本采集；
//! 3. 汇总软件版本、系统版本、五项安全检测状态及最近 30 条运行日志。

use chrono::Local;

use crate::checker::LightStatus;
use crate::forwarder::ForwarderStateSnapshot;
use crate::logger::LogKind;
use crate::AppContext;

/// 采集当前操作系统人类可读版本信息（双端原生适配）
pub fn detect_os_version_string() -> String {
    #[cfg(windows)]
    {
        detect_windows_version()
    }

    #[cfg(target_os = "macos")]
    {
        detect_macos_version()
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH)
    }
}

#[cfg(windows)]
fn detect_windows_version() -> String {
    let product = read_hklm_nt_string("ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let display_ver = read_hklm_nt_string("DisplayVersion")
        .or_else(|| read_hklm_nt_string("ReleaseId"))
        .unwrap_or_default();
    let build_str = read_hklm_nt_string("CurrentBuildNumber")
        .or_else(|| read_hklm_nt_string("CurrentBuild"))
        .unwrap_or_default();
    let ubr_opt = read_hklm_nt_dword("UBR");

    let build_num: u32 = build_str.trim().parse().unwrap_or(0);
    // Windows 11 的注册表 ProductName 仍为 "Windows 10 ..."，需依据 Build >= 22000 精准修正
    let normalized_product = if build_num >= 22000 && product.contains("Windows 10") {
        product.replace("Windows 10", "Windows 11")
    } else {
        product
    };

    let full_build = match (build_str.is_empty(), ubr_opt) {
        (false, Some(ubr)) => format!("Build {}.{}", build_str, ubr),
        (false, None) => format!("Build {}", build_str),
        _ => String::new(),
    };

    let ver_part = if display_ver.is_empty() {
        String::new()
    } else {
        format!(" {}", display_ver)
    };

    if full_build.is_empty() {
        format!("{}{} ({})", normalized_product, ver_part, std::env::consts::ARCH)
    } else {
        format!(
            "{}{} ({}, {})",
            normalized_product,
            ver_part,
            full_build,
            std::env::consts::ARCH
        )
    }
}

#[cfg(windows)]
fn read_hklm_nt_string(value_name: &str) -> Option<String> {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ,
    };

    let subkey: Vec<u16> = OsStr::new(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_wide: Vec<u16> = OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if rc != 0 || hkey.is_null() {
        return None;
    }

    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 0;
    let q_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_wide.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            ptr::null_mut(),
            &mut byte_len,
        )
    };
    if q_rc != 0 || byte_len == 0 || (val_type != REG_SZ && val_type != REG_EXPAND_SZ) {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let u16_cap = (byte_len as usize).div_ceil(2) + 1;
    let mut buf = vec![0u16; u16_cap];
    let mut actual = (buf.len() * 2) as u32;
    let read_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_wide.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut actual,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if read_rc != 0 {
        return None;
    }

    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(windows)]
fn read_hklm_nt_dword(value_name: &str) -> Option<u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY, REG_DWORD,
    };

    let subkey: Vec<u16> = OsStr::new(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_wide: Vec<u16> = OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if rc != 0 || hkey.is_null() {
        return None;
    }

    let mut val_type: u32 = 0;
    let mut out_val: u32 = 0;
    let mut byte_len: u32 = 4;
    let q_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_wide.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            &mut out_val as *mut u32 as *mut u8,
            &mut byte_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }

    if q_rc == 0 && val_type == REG_DWORD {
        Some(out_val)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn detect_macos_version() -> String {
    use std::process::Command;

    let run_sw_vers = |flag: &str| -> Option<String> {
        Command::new("/usr/bin/sw_vers")
            .arg(flag)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };

    let name = run_sw_vers("-productName").unwrap_or_else(|| "macOS".to_string());
    let ver = run_sw_vers("-productVersion").unwrap_or_default();
    let build = run_sw_vers("-buildVersion").unwrap_or_default();

    match (ver.is_empty(), build.is_empty()) {
        (false, false) => format!("{} {} (Build {}, {})", name, ver, build, std::env::consts::ARCH),
        (false, true) => format!("{} {} ({})", name, ver, std::env::consts::ARCH),
        _ => format!("{} ({})", name, std::env::consts::ARCH),
    }
}

/// 对主机地址（IPv4 / IPv6 / 域名）执行 `***` 脱敏
pub fn mask_sensitive_host(host: &str) -> String {
    let trimmed = host.trim().trim_matches(|c| c == '[' || c == ']');
    if trimmed.is_empty() {
        return "***".to_string();
    }
    if trimmed == "127.0.0.1" || trimmed.eq_ignore_ascii_case("localhost") {
        return trimmed.to_string();
    }

    // IPv4: 保留前两段，后两段掩码为 ***
    let dot_parts: Vec<&str> = trimmed.split('.').collect();
    if dot_parts.len() == 4 && dot_parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        return format!("{}.{}.***.***", dot_parts[0], dot_parts[1]);
    }

    // IPv6: 保留首段 + ***
    if trimmed.contains(':') {
        let first = trimmed.split(':').next().unwrap_or("");
        return if first.is_empty() {
            "***:***".to_string()
        } else {
            format!("{}:****:***", first)
        };
    }

    // 域名: 保留首 2 个字符与顶级后缀，中间用 *** 替换
    if let Some((_, tld)) = trimmed.rsplit_once('.') {
        let prefix: String = trimmed.chars().take(2).collect();
        format!("{}***.{}", prefix, tld)
    } else {
        let prefix: String = trimmed.chars().take(2).collect();
        format!("{}***", prefix)
    }
}

/// 对完整授权码（如 `CL-ABCD-EFGH-IJKL-MNOP`）执行 `***` 脱敏
pub fn mask_license_code(code: &str) -> String {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return "***".to_string();
    }
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() == 5 && parts[0].eq_ignore_ascii_case("CL") {
        format!("CL-{}-***-***-{}", parts[1], parts[4])
    } else if trimmed.chars().count() > 6 {
        let head: String = trimmed.chars().take(3).collect();
        let tail: String = trimmed
            .chars()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}***{}", head, tail)
    } else {
        "***".to_string()
    }
}

/// 扫描任意文本中的 `CL-XXXX-XXXX-XXXX-XXXX` 形态授权码及公网 IPv4 地址并统一替换为 `***` 脱敏格式
pub fn scrub_text_for_diagnostics(
    raw: &str,
    known_hosts: &[String],
    known_codes: &[String],
) -> String {
    let mut out = raw.replace("[REDACTED]", "***");

    // 1. 替换已知完整授权码
    for code in known_codes {
        if !code.trim().is_empty() && out.contains(code) {
            out = out.replace(code, &mask_license_code(code));
        }
    }

    // 2. 替换已知敏感代理域名/地址（按长度降序防止子串残缺）
    let mut sorted_hosts: Vec<&String> = known_hosts
        .iter()
        .filter(|h| {
            let t = h.trim();
            !t.is_empty() && t != "127.0.0.1" && !t.eq_ignore_ascii_case("localhost")
        })
        .collect();
    sorted_hosts.sort_by(|a, b| b.len().cmp(&a.len()));
    for h in sorted_hosts {
        if out.contains(h.as_str()) {
            out = out.replace(h.as_str(), &mask_sensitive_host(h));
        }
    }

    // 3. 模式扫描并掩码残余的 CL-XXXX-XXXX-XXXX-XXXX 授权码与非回环 IPv4
    out = redact_inline_license_codes(&out);
    out = redact_non_loopback_ipv4(&out);
    out
}

fn redact_inline_license_codes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        // 匹配 22 字节形如 CL-XXXX-XXXX-XXXX-XXXX
        if i + 22 <= bytes.len()
            && (bytes[i] == b'C' || bytes[i] == b'c')
            && (bytes[i + 1] == b'L' || bytes[i + 1] == b'l')
            && bytes[i + 2] == b'-'
            && bytes[i + 7] == b'-'
            && bytes[i + 12] == b'-'
            && bytes[i + 17] == b'-'
            && bytes[i + 3..i + 7].iter().all(|b| b.is_ascii_alphanumeric())
            && bytes[i + 8..i + 12].iter().all(|b| b.is_ascii_alphanumeric())
            && bytes[i + 13..i + 17].iter().all(|b| b.is_ascii_alphanumeric())
            && bytes[i + 18..i + 22].iter().all(|b| b.is_ascii_alphanumeric())
        {
            let matched = &input[i..i + 22];
            out.push_str(&mask_license_code(matched));
            i += 22;
            continue;
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn redact_non_loopback_ipv4(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i].is_ascii_digit() {
            // 向前检查：若紧挨字母或点则不是独立 IPv4 起点
            let prev_ok = if i == 0 {
                true
            } else {
                !chars[i - 1].is_ascii_alphanumeric() && chars[i - 1] != '.'
            };

            if prev_ok {
                let mut j = i;
                while j < len && (chars[j].is_ascii_digit() || chars[j] == '.') {
                    j += 1;
                }
                let next_ok = if j == len {
                    true
                } else {
                    !chars[j].is_ascii_alphanumeric() && chars[j] != '.'
                };

                if next_ok {
                    let token: String = chars[i..j].iter().collect();
                    let segs: Vec<&str> = token.split('.').collect();
                    if segs.len() == 4
                        && segs.iter().all(|s| !s.is_empty() && s.len() <= 3 && s.parse::<u8>().is_ok())
                    {
                        if token == "127.0.0.1" || token == "0.0.0.0" {
                            result.push_str(&token);
                        } else {
                            result.push_str(&format!("{}.{}.***.***", segs[0], segs[1]));
                        }
                        i = j;
                        continue;
                    }
                }
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

fn status_cn(st: LightStatus) -> &'static str {
    match st {
        LightStatus::Green => "通过 (绿灯)",
        LightStatus::Yellow => "警告 (黄灯)",
        LightStatus::Red => "阻断/失败 (红灯)",
        LightStatus::Checking => "检测中",
        LightStatus::Pending => "待定",
    }
}

/// 生成完整的一键脱敏诊断报告文本
pub fn build_sanitized_diagnostic_report(ctx: &AppContext) -> String {
    let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let app_version = env!("CARGO_PKG_VERSION");
    let os_version = detect_os_version_string();

    let (proxies, active_proxy_id) = ctx.proxy_store.list_proxies();
    let settings = ctx.proxy_store.get_settings();
    let license_view = ctx.proxy_store.get_license_status();
    let stored_lic = ctx.proxy_store.get_stored_license_payload();
    let (envs, active_env_id) = ctx.proxy_store.list_browser_envs();
    let active_env_name = envs
        .iter()
        .find(|e| e.id == active_env_id)
        .map(|e| e.name.as_str())
        .unwrap_or("默认环境");

    let mut known_hosts: Vec<String> = proxies.iter().map(|p| p.host.clone()).collect();
    if let Some(rep) = ctx.checker.latest_report() {
        if let Some(ip) = rep.exit_ip {
            known_hosts.push(ip);
        }
    }

    let mut known_codes: Vec<String> = Vec::new();
    if let Some(ref lic) = stored_lic {
        known_codes.push(lic.code.clone());
        if !lic.phone.trim().is_empty() {
            // 手机号也纳入已知脱敏保护
            known_codes.push(lic.phone.clone());
        }
    }

    let active_proxy_desc = active_proxy_id
        .as_ref()
        .and_then(|aid| proxies.iter().find(|p| &p.id == aid))
        .map(|p| {
            format!(
                "{} (socks5://{}:{}, 认证={})",
                p.name,
                mask_sensitive_host(&p.host),
                p.port,
                if p.auth_enabled { "已开启 ***" } else { "未开启" }
            )
        })
        .unwrap_or_else(|| "未选择激活节点".to_string());

    let license_desc = if license_view.authorized {
        let masked_code = stored_lic
            .as_ref()
            .map(|s| mask_license_code(&s.code))
            .unwrap_or_else(|| "CL-***".to_string());
        let validity = if license_view.is_permanent {
            "永久授权".to_string()
        } else if let Some(days) = license_view.days_remaining {
            format!(
                "剩余 {} 天 (至 {})",
                days.max(0),
                license_view.expires_at.as_deref().unwrap_or("-")
            )
        } else {
            format!("至 {}", license_view.expires_at.as_deref().unwrap_or("-"))
        };
        format!(
            "已授权 | 授权码={} | 有效期={} | 设备码={}",
            masked_code, validity, license_view.machine_code
        )
    } else {
        format!("未授权 | 设备码={}", license_view.machine_code)
    };

    let forwarder_desc = match ctx.forwarder_mgr.snapshot() {
        ForwarderStateSnapshot::Running {
            port,
            active_connections,
            lease_count,
        } => format!(
            "运行中 (127.0.0.1:{}, 活跃连接={}, 租约数={})",
            port, active_connections, lease_count
        ),
        ForwarderStateSnapshot::Tripped { reason } => format!("已紧急熔断 ({})", reason),
        ForwarderStateSnapshot::Stopped => "已停止".to_string(),
    };

    let cb = ctx.watchdog.snapshot();
    let mut lines: Vec<String> = Vec::new();
    lines.push("================ Claude安全客户端 · 脱敏诊断报告 ================".to_string());
    lines.push(format!("生成时间: {}", now_str));
    lines.push(format!("软件版本: v{}", app_version));
    lines.push(format!("系统版本: {}", os_version));
    lines.push(format!("授权状态: {}", license_desc));
    lines.push(format!("当前节点: {}", active_proxy_desc));
    lines.push(format!("浏览器环境: {} (共 {} 个独立环境)", active_env_name, envs.len()));
    lines.push(format!("本地转发器: {}", forwarder_desc));
    lines.push(format!(
        "安全守护: 安全模式={} | 巡检周期={}s | 开机自启={} | 熔断锁定={}",
        if settings.safe_mode_enabled { "开启" } else { "关闭" },
        settings.watchdog_interval_sec,
        if settings.auto_start_enabled { "开启" } else { "关闭" },
        if cb.locked { "是" } else { "否" }
    ));

    lines.push("---------------- 五项安全检测状态 ----------------".to_string());
    if let Some(rep) = ctx.checker.latest_report() {
        let masked_exit_ip = rep
            .exit_ip
            .as_deref()
            .map(mask_sensitive_host)
            .unwrap_or_else(|| "未获取".to_string());
        lines.push(format!(
            "检测节点: {} | 出口IP: {} | 国家/地区: {} | 风险分: {}",
            rep.proxy_name,
            masked_exit_ip,
            rep.country_display.as_deref().unwrap_or("-"),
            rep.risk_score
                .map(|s| format!("{}/100", s))
                .unwrap_or_else(|| "-".to_string())
        ));
        for item in &rep.items {
            let lat = item
                .latency_ms
                .map(|ms| format!(" ({}ms)", ms))
                .unwrap_or_default();
            let raw_sum = ctx.logger.sanitize(&item.summary);
            let safe_sum = scrub_text_for_diagnostics(&raw_sum, &known_hosts, &known_codes);
            lines.push(format!(
                "  [0{} {}] {}{} - {}",
                item.index,
                item.title,
                status_cn(item.status),
                lat,
                safe_sum
            ));
        }
    } else {
        lines.push("  尚未执行五项安全检测".to_string());
    }

    lines.push("---------------- 最近 30 条运行日志 (已 *** 脱敏) ----------------".to_string());
    let mut merged_logs: Vec<String> = Vec::new();
    for (kind, tag) in [
        (LogKind::App, "app"),
        (LogKind::Check, "check"),
        (LogKind::Launch, "launch"),
    ] {
        if let Ok(tail) = ctx.logger.read_tail(kind, Some(30)) {
            for entry in tail {
                // 原格式: [2026-11-26 00:10:00.123] [INFO] xxx
                // 保持时间戳在最前以便跨分类按时间精确排序
                if let Some(close_bracket) = entry.find(']') {
                    let ts_part = &entry[..=close_bracket];
                    let rest = &entry[close_bracket + 1..];
                    merged_logs.push(format!("{} [{}]{}", ts_part, tag, rest));
                } else {
                    merged_logs.push(format!("[{}] {}", tag, entry));
                }
            }
        }
    }

    merged_logs.sort();
    let start_idx = merged_logs.len().saturating_sub(30);
    let recent_30 = &merged_logs[start_idx..];
    if recent_30.is_empty() {
        lines.push("  (暂无运行日志记录)".to_string());
    } else {
        for raw_line in recent_30 {
            let step1 = ctx.logger.sanitize(raw_line);
            let step2 = scrub_text_for_diagnostics(&step1, &known_hosts, &known_codes);
            lines.push(format!("  {}", step2));
        }
    }
    lines.push("=================================================================".to_string());

    lines.join("\n")
}
