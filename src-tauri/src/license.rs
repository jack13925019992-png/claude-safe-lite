//! 软件云端一机一码授权核销模块（Cloudflare Workers + Ed25519 响应防伪验签 + 本机机器码绑定）
//!
//! 核心能力：
//! 1. 发卡时无需向客户索要姓名、手机号或机器码，管理员直接生成 `CL-XXXX-XXXX-XXXX-XXXX` 短码；
//! 2. 客户首次在客户端输入「姓名 + 手机号 + 授权码」登录时，云端原子锁死该电脑硬件机器码，转发给第二台电脑立即拦截；
//! 3. 支持「直连 + SOCKS5 本地转发器」双通道自动穿透请求云端，国内海外网络均稳定可达；
//! 4. 云端响应带 Ed25519 私钥签名，客户端使用内置公钥验签并经 Windows DPAPI 加密落盘，彻底防御改 Hosts 或抓包改包破解。

use std::sync::OnceLock;
use std::time::Duration;

use chrono::{Local, NaiveDate};
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::constants::LICENSE_CLOUD_VERIFY_URL;

/// 唯一验证公钥（对应云端 Worker 中的 `ED25519_SEED_HEX` 私钥种子，客户端绝不持有私钥）
const LICENSE_ED25519_PUBKEY: [u8; 32] = [
    0x74, 0xb6, 0x30, 0x06, 0x8b, 0x39, 0x49, 0x63,
    0xf4, 0x1a, 0xd9, 0xb6, 0x88, 0x4e, 0x21, 0x62,
    0xc5, 0xef, 0x64, 0x46, 0x52, 0x6d, 0xfd, 0x1b,
    0xc3, 0x15, 0x47, 0x70, 0xec, 0x1d, 0x1d, 0x24,
];

static CACHED_MACHINE_CODE: OnceLock<String> = OnceLock::new();

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("请填写您的姓名（1–64 个字符）")]
    InvalidName,
    #[error("请填写正确的手机号码")]
    InvalidPhone,
    #[error("授权码格式不正确 → 请输入形如 CL-XXXX-XXXX-XXXX-XXXX 的授权码")]
    InvalidFormat,
    #[error("{0}")]
    CloudRejected(String),
    #[error("云端授权响应签名校验失败 → 疑似网络劫持或非法伪造响应")]
    InvalidServerSignature,
    #[error("无法连接云端授权验证服务 → 请在下方填写可用的 SOCKS5 代理后重试 ({0})")]
    NetworkUnreachable(String),
    #[error("您的软件授权已于 {0} 到期 → 请联系管理员获取新的续期授权码")]
    Expired(String),
}

/// 经 Windows DPAPI 加密后保存在 `config.json` 中的本机授权通行证
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredLicensePayload {
    pub code: String,
    pub machine_code: String,
    pub name: String,
    pub phone: String,
    pub is_permanent: bool,
    pub expires_at: String,
    pub issued_unix: u64,
    pub signature_hex: String,
    pub activated_at: String,
}

/// 下发给前端展示的授权状态快照
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatusView {
    pub authorized: bool,
    pub machine_code: String,
    pub holder_name: Option<String>,
    pub holder_phone: Option<String>,
    pub is_permanent: bool,
    pub expires_at: Option<String>,
    pub days_remaining: Option<i64>,
    pub machine_bound: bool,
    pub expired_message: Option<String>,
}

impl LicenseStatusView {
    pub fn unauthorized_default(
        prev_name: Option<String>,
        prev_phone: Option<String>,
        expired_message: Option<String>,
    ) -> Self {
        Self {
            authorized: false,
            machine_code: get_machine_code(),
            holder_name: prev_name,
            holder_phone: prev_phone,
            is_permanent: false,
            expires_at: None,
            days_remaining: None,
            machine_bound: true,
            expired_message,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CloudVerifyRequest<'a> {
    code: &'a str,
    name: &'a str,
    phone: &'a str,
    machine_code: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudVerifyResponse {
    ok: bool,
    #[serde(default)]
    code: String,
    #[serde(default)]
    machine_code: String,
    #[serde(default, rename = "isPermanent")]
    _is_permanent: bool,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    holder_name: String,
    #[serde(default)]
    holder_phone: String,
    #[serde(default)]
    issued_unix: u64,
    #[serde(default)]
    signature_hex: String,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    message: String,
}

/// 云端后台复验结果
pub enum HeartbeatOutcome {
    Valid(StoredLicensePayload),
    RevokedOrInvalid(String),
    TransientNetworkError,
}

pub fn normalize_name(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn normalize_phone(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx == 0 && ch == '+' {
            out.push('+');
        } else if ch.is_ascii_digit() {
            out.push(ch);
        }
    }
    out
}

/// 规范化 20 位云端短授权码：`CL-XXXX-XXXX-XXXX-XXXX`
pub fn normalize_short_code(raw: &str) -> Result<String, LicenseError> {
    let alnum: String = raw
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let body = alnum.strip_prefix("CL").unwrap_or(&alnum);
    if body.len() != 16 {
        return Err(LicenseError::InvalidFormat);
    }
    Ok(format!(
        "CL-{}-{}-{}-{}",
        &body[0..4],
        &body[4..8],
        &body[8..12],
        &body[12..16]
    ))
}

/// 获取本机底层硬件唯一标识原始种子（Windows MachineGuid / macOS IOPlatformUUID）
pub(crate) fn raw_hardware_identity_seed() -> String {
    #[cfg(windows)]
    {
        if let Some(guid) = read_windows_machine_guid() {
            return guid;
        }
        let comp = std::env::var("COMPUTERNAME").unwrap_or_default();
        let user = std::env::var("USERNAME").unwrap_or_default();
        let arch = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default();
        format!("FALLBACK|{}|{}|{}", comp, user, arch)
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(uuid) = read_macos_platform_uuid() {
            return uuid;
        }
        let host = std::process::Command::new("/bin/hostname")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let user = std::env::var("USER").unwrap_or_default();
        format!("FALLBACK-MAC|{}|{}|{}", host, user, std::env::consts::ARCH)
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = mid.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let user = std::env::var("USER").unwrap_or_default();
        format!("FALLBACK-UNIX|{}|{}", user, std::env::consts::ARCH)
    }
}

/// 获取本机稳定硬件机器码（格式：`MC-XXXX-XXXX-XXXX`）
pub fn get_machine_code() -> String {
    CACHED_MACHINE_CODE
        .get_or_init(|| {
            let raw_guid = raw_hardware_identity_seed();
            let seed_input = format!("CSL-HWID-V1|{}", raw_guid.trim().to_ascii_lowercase());
            let hash = digest(&SHA256, seed_input.as_bytes());
            let bytes = hash.as_ref();
            let hex_12 = format!(
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            );
            format!("MC-{}-{}-{}", &hex_12[0..4], &hex_12[4..8], &hex_12[8..12])
        })
        .clone()
}

#[cfg(windows)]
fn read_windows_machine_guid() -> Option<String> {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ,
    };

    let subkey: Vec<u16> = OsStr::new(r"SOFTWARE\Microsoft\Cryptography")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let val_name: Vec<u16> = OsStr::new("MachineGuid")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey: HKEY = ptr::null_mut();
    let open_rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if open_rc != 0 || hkey.is_null() {
        return None;
    }

    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 0;
    let size_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            ptr::null_mut(),
            &mut byte_len,
        )
    };
    if size_rc != 0 || byte_len < 4 || (val_type != REG_SZ && val_type != REG_EXPAND_SZ) {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let u16_cap = (byte_len as usize + 1) / 2;
    let mut buf: Vec<u16> = vec![0u16; u16_cap];
    let read_rc = unsafe {
        RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut byte_len,
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

#[cfg(target_os = "macos")]
fn read_macos_platform_uuid() -> Option<String> {
    use std::process::Command;

    // 1. 首选苹果 I/O Kit 注册表读取主板硬件唯一标识 IOPlatformUUID（极速、免权限）
    if let Ok(out) = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some((_, rhs)) = line.split_once('=') {
                        let cleaned = rhs.trim().trim_matches('"').trim();
                        if cleaned.len() >= 16 {
                            return Some(cleaned.to_string());
                        }
                    }
                }
            }
        }
    }

    // 2. 备用：通过 system_profiler 读取 Hardware UUID
    if let Ok(out) = Command::new("/usr/sbin/system_profiler")
        .arg("SPHardwareDataType")
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("Hardware UUID:") {
                    let uuid = rest.trim();
                    if uuid.len() >= 16 {
                        return Some(uuid.to_string());
                    }
                }
            }
        }
    }

    None
}

fn decode_hex_64(hex: &str) -> Option<[u8; 64]> {
    let trimmed = hex.trim();
    if trimmed.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// 校验云端或本地缓存票据的 Ed25519 数字签名与设备机器码一致性
pub fn verify_signed_ticket(
    code: &str,
    machine_code: &str,
    expires_at: &str,
    issued_unix: u64,
    signature_hex: &str,
) -> Result<(bool, Option<i64>), LicenseError> {
    let current_mc = get_machine_code();
    if machine_code != current_mc {
        return Err(LicenseError::CloudRejected(
            "本机设备识别码与授权凭证不匹配，请重新输入授权码验证".to_string(),
        ));
    }

    let sig_bytes = decode_hex_64(signature_hex).ok_or(LicenseError::InvalidServerSignature)?;
    let msg = format!(
        "CSL-CLOUD-V2|{}|{}|{}|{}",
        code, machine_code, expires_at, issued_unix
    );

    let pub_key = UnparsedPublicKey::new(&ED25519, &LICENSE_ED25519_PUBKEY);
    if pub_key.verify(msg.as_bytes(), &sig_bytes).is_err() {
        return Err(LicenseError::InvalidServerSignature);
    }

    if expires_at == "永久有效" {
        return Ok((true, None));
    }

    let exp_date = NaiveDate::parse_from_str(expires_at, "%Y-%m-%d")
        .map_err(|_| LicenseError::InvalidServerSignature)?;
    let today = Local::now().date_naive();
    if today > exp_date {
        return Err(LicenseError::Expired(expires_at.to_string()));
    }

    let remain = (exp_date - today).num_days();
    Ok((false, Some(remain)))
}

async fn post_verify_once(
    req_body: &CloudVerifyRequest<'_>,
    local_socks_port: Option<u16>,
) -> Result<CloudVerifyResponse, String> {
    let mut builder = reqwest::Client::builder();
    if let Some(port) = local_socks_port {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", port))
            .map_err(|e| e.to_string())?;
        builder = builder
            .proxy(proxy)
            .timeout(Duration::from_secs(12));
    } else {
        builder = builder
            .no_proxy()
            .timeout(Duration::from_secs(5));
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .post(LICENSE_CLOUD_VERIFY_URL)
        .json(req_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let parsed: CloudVerifyResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed)
}

/// 向云端发起首次激活或绑定核验（直连优先 → 失败自动切换本地 SOCKS5 转发器穿透）
pub async fn activate_with_cloud(
    raw_name: &str,
    raw_phone: &str,
    raw_code: &str,
    fallback_socks_port: Option<u16>,
) -> Result<StoredLicensePayload, LicenseError> {
    let norm_name = normalize_name(raw_name);
    if norm_name.is_empty() || norm_name.chars().count() > 64 {
        return Err(LicenseError::InvalidName);
    }

    let norm_phone = normalize_phone(raw_phone);
    let digits = norm_phone.chars().filter(|c| c.is_ascii_digit()).count();
    if digits < 6 || digits > 20 {
        return Err(LicenseError::InvalidPhone);
    }

    let norm_code = normalize_short_code(raw_code)?;
    let machine_code = get_machine_code();

    let req_body = CloudVerifyRequest {
        code: &norm_code,
        name: &norm_name,
        phone: &norm_phone,
        machine_code: &machine_code,
    };

    // 1. 先尝试直连云端；若直连网络不通且存在可用代理端口，自动走 SOCKS5 代理重试
    let cloud_resp = match post_verify_once(&req_body, None).await {
        Ok(r) => r,
        Err(direct_err) => {
            if let Some(port) = fallback_socks_port {
                post_verify_once(&req_body, Some(port))
                    .await
                    .map_err(|proxy_err| {
                        LicenseError::NetworkUnreachable(format!(
                            "直连失败 ({})；经代理转发亦失败 ({})",
                            direct_err, proxy_err
                        ))
                    })?
            } else {
                return Err(LicenseError::NetworkUnreachable(direct_err));
            }
        }
    };

    if !cloud_resp.ok {
        let msg = if cloud_resp.message.is_empty() {
            format!("授权校验未通过 ({})", cloud_resp.error_code)
        } else {
            cloud_resp.message
        };
        return Err(LicenseError::CloudRejected(msg));
    }

    // 2. 严格使用内置 Ed25519 公钥校验云端签名，防止中间人伪造响应
    let (is_permanent, _) = verify_signed_ticket(
        &cloud_resp.code,
        &cloud_resp.machine_code,
        &cloud_resp.expires_at,
        cloud_resp.issued_unix,
        &cloud_resp.signature_hex,
    )?;

    Ok(StoredLicensePayload {
        code: cloud_resp.code,
        machine_code: cloud_resp.machine_code,
        name: if cloud_resp.holder_name.is_empty() {
            norm_name
        } else {
            cloud_resp.holder_name
        },
        phone: if cloud_resp.holder_phone.is_empty() {
            norm_phone
        } else {
            cloud_resp.holder_phone
        },
        is_permanent,
        expires_at: cloud_resp.expires_at,
        issued_unix: cloud_resp.issued_unix,
        signature_hex: cloud_resp.signature_hex,
        activated_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

/// 后台静默向云端复验已存授权（检测管理员是否远程封禁、删除或解绑了该授权码）
pub async fn heartbeat_check_cloud(
    stored: &StoredLicensePayload,
    fallback_socks_port: Option<u16>,
) -> HeartbeatOutcome {
    let req_body = CloudVerifyRequest {
        code: &stored.code,
        name: &stored.name,
        phone: &stored.phone,
        machine_code: &stored.machine_code,
    };

    let resp = match post_verify_once(&req_body, None).await {
        Ok(r) => r,
        Err(_) => {
            if let Some(port) = fallback_socks_port {
                match post_verify_once(&req_body, Some(port)).await {
                    Ok(r) => r,
                    Err(_) => return HeartbeatOutcome::TransientNetworkError,
                }
            } else {
                return HeartbeatOutcome::TransientNetworkError;
            }
        }
    };

    if !resp.ok {
        let reason = if resp.message.is_empty() {
            "该授权码已失效或已被管理员停用".to_string()
        } else {
            resp.message
        };
        return HeartbeatOutcome::RevokedOrInvalid(reason);
    }

    if let Ok((is_perm, _)) = verify_signed_ticket(
        &resp.code,
        &resp.machine_code,
        &resp.expires_at,
        resp.issued_unix,
        &resp.signature_hex,
    ) {
        HeartbeatOutcome::Valid(StoredLicensePayload {
            code: resp.code,
            machine_code: resp.machine_code,
            name: if resp.holder_name.is_empty() {
                stored.name.clone()
            } else {
                resp.holder_name
            },
            phone: if resp.holder_phone.is_empty() {
                stored.phone.clone()
            } else {
                resp.holder_phone
            },
            is_permanent: is_perm,
            expires_at: resp.expires_at,
            issued_unix: resp.issued_unix,
            signature_hex: resp.signature_hex,
            activated_at: stored.activated_at.clone(),
        })
    } else {
        HeartbeatOutcome::TransientNetworkError
    }
}
