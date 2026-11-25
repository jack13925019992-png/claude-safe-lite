//! 多套代理配置、原子持久化与快捷粘贴解析模块（ProxyStore）
//!
//! 职责：
//! 1. 管理 `%APPDATA%\ClaudeSafeLite\config.json` 及 `.bak` 原子回退；
//! 2. 密码强制使用 Windows DPAPI 加密存储，前端视图仅暴露 `hasPassword: bool`（零明文持有）；
//! 3. 支持代理 CRUD、复制、激活切换与 `host:port:user:pass` / `socks5://user:pass@host:port` 解析。

use std::fs::{self, File};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::constants::{
    APP_DATA_DIR_NAME, CONFIG_BACKUP_FILE_NAME, CONFIG_FILE_NAME, CONFIG_SCHEMA_VERSION,
    CONFIG_TEMP_FILE_NAME, PROFILES_DIR_NAME, WATCHDOG_ALLOWED_INTERVALS,
    WATCHDOG_DEFAULT_INTERVAL_SECS,
};
use crate::crypto::{dpapi_decrypt, dpapi_encrypt, CryptoError};
use crate::license::{
    get_machine_code, verify_signed_ticket, LicenseError, LicenseStatusView, StoredLicensePayload,
};
use crate::logger::{LogKind, Logger};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("无法定位系统 APPDATA 目录")]
    AppDataNotFound,
    #[error("配置文件读写失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("配置序列化失败: {0}")]
    Json(#[from] serde_json::Error),
    #[error("密码安全加解密失败: {0}")]
    Crypto(#[from] CryptoError),
    #[error("配置校验失败: {0}")]
    Validation(String),
    #[error("未找到指定的代理配置")]
    ProxyNotFound,
    #[error("代理文本格式无法识别: {0}")]
    ParseError(String),
    #[error("{0}")]
    License(#[from] LicenseError),
    #[error("软件尚未激活授权或授权已失效，请先完成授权访问验证")]
    Unauthorized,
}

/// 全局应用设置（持久化至 `config.json`）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub custom_browser_path: Option<String>,
    #[serde(default = "default_safe_mode")]
    pub safe_mode_enabled: bool,
    #[serde(default = "default_watchdog_interval")]
    pub watchdog_interval_sec: u64,
}

fn default_safe_mode() -> bool {
    true
}

fn default_watchdog_interval() -> u64 {
    WATCHDOG_DEFAULT_INTERVAL_SECS
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            custom_browser_path: None,
            safe_mode_enabled: true,
            watchdog_interval_sec: WATCHDOG_DEFAULT_INTERVAL_SECS,
        }
    }
}

impl AppSettings {
    /// 校验并规范化应用设置
    pub fn validate_and_normalize(&mut self) -> Result<(), StoreError> {
        if !WATCHDOG_ALLOWED_INTERVALS.contains(&self.watchdog_interval_sec) {
            return Err(StoreError::Validation(format!(
                "安全巡检周期仅支持 {:?} 秒",
                WATCHDOG_ALLOWED_INTERVALS
            )));
        }
        if let Some(ref raw_path) = self.custom_browser_path {
            let trimmed = raw_path.trim();
            if trimmed.is_empty() {
                self.custom_browser_path = None;
            } else {
                let pb = PathBuf::from(trimmed);
                if crate::browser_launcher::resolve_browser_executable_path(&pb).is_none() {
                    return Err(StoreError::Validation(
                        "手动指定的浏览器路径不存在或无效（macOS 可直接填写 .app 路径，Windows 请填写 .exe 路径）"
                            .to_string(),
                    ));
                }
                self.custom_browser_path = Some(trimmed.to_string());
            }
        }
        Ok(())
    }
}

/// 磁盘持久化的单条代理结构（含 DPAPI Base64 密文，绝不下发前端）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredProxy {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth_enabled: bool,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_encrypted: String,
}

/// `config.json` 顶层磁盘 Schema（严格对应需求文档 8.1）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfigFile {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub active_proxy_id: Option<String>,
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub proxies: Vec<StoredProxy>,
    /// 经 Windows DPAPI 加密存储的本机授权凭证（跨机器拷贝失效）
    #[serde(default)]
    pub license_encrypted: Option<String>,
}

fn default_schema_version() -> u32 {
    CONFIG_SCHEMA_VERSION
}

impl Default for AppConfigFile {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            active_proxy_id: None,
            settings: AppSettings::default(),
            proxies: Vec::new(),
            license_encrypted: None,
        }
    }
}

/// 下发给前端的安全代理视图（零密码字段，仅含 `hasPassword`）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyView {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth_enabled: bool,
    pub username: String,
    pub has_password: bool,
}

impl From<&StoredProxy> for ProxyView {
    fn from(sp: &StoredProxy) -> Self {
        Self {
            id: sp.id.clone(),
            name: sp.name.clone(),
            host: sp.host.clone(),
            port: sp.port,
            auth_enabled: sp.auth_enabled,
            username: sp.username.clone(),
            has_password: !sp.password_encrypted.trim().is_empty(),
        }
    }
}

/// 仅供后端 Forwarder 内部建连时瞬时使用的解密上游配置
#[derive(Debug, Clone)]
pub struct ResolvedUpstreamProxy {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl Drop for ResolvedUpstreamProxy {
    fn drop(&mut self) {
        if let Some((_, ref mut pwd)) = self.auth {
            // SAFETY: 将密码底层字节清零后再释放，降低内存驻留时间
            unsafe {
                pwd.as_bytes_mut().fill(0);
            }
        }
    }
}

/// 前端新增或编辑保存代理的输入契约
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveProxyInput {
    pub id: Option<String>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth_enabled: bool,
    #[serde(default)]
    pub username: String,
    /// 新建开启认证时必填；编辑时若为 `None` 或空串，表示沿用已保存的原密码
    pub password: Option<String>,
}

/// 快捷粘贴解析结果（用于回填前端表单，尚未落盘）
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedProxyDraft {
    pub host: String,
    pub port: u16,
    pub auth_enabled: bool,
    pub username: String,
    pub password: String,
}

/// 定位 `%APPDATA%\ClaudeSafeLite` 根目录
pub fn resolve_default_app_data_dir() -> Result<PathBuf, StoreError> {
    let roaming = dirs::config_dir().ok_or(StoreError::AppDataNotFound)?;
    Ok(roaming.join(APP_DATA_DIR_NAME))
}

/// 校验并规范化代理主机地址（支持域名、IPv4、带或不带方括号的 IPv6）
pub fn validate_and_normalize_host(raw_host: &str) -> Result<String, StoreError> {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() {
        return Err(StoreError::Validation("代理主机地址不能为空".to_string()));
    }
    if trimmed.contains("://") || trimmed.contains('/') || trimmed.chars().any(char::is_whitespace)
    {
        return Err(StoreError::Validation(
            "代理主机地址不应包含协议头(socks5://)、斜杠或空格".to_string(),
        ));
    }

    // 1. 带方括号的 IPv6，例如 [2001:db8::1]
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let ipv6 = Ipv6Addr::from_str(inner)
            .map_err(|_| StoreError::Validation("IPv6 地址格式不合法".to_string()))?;
        return Ok(ipv6.to_string());
    }

    // 2. 裸 IPv6
    if trimmed.contains(':') {
        let ipv6 = Ipv6Addr::from_str(trimmed)
            .map_err(|_| StoreError::Validation("IPv6 地址格式不合法（请检查冒号段或是否误带端口）".to_string()))?;
        return Ok(ipv6.to_string());
    }

    // 3. IPv4
    if let Ok(ipv4) = Ipv4Addr::from_str(trimmed) {
        return Ok(ipv4.to_string());
    }

    // 若全部由数字和点组成但上面 IPv4 解析失败（例如 999.1.1.1 或 1.2.3），明确拦截
    if trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(StoreError::Validation(
            "IPv4 地址格式不合法（每段须为 0-255 的四段十进制数）".to_string(),
        ));
    }

    // 4. 域名校验（RFC 1035 / 1123）
    if trimmed.len() > 253 {
        return Err(StoreError::Validation("域名总长度不能超过 253 个字符".to_string()));
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return Err(StoreError::Validation("域名格式不合法（存在连续点或首尾点）".to_string()));
    }
    for label in &labels {
        if label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(StoreError::Validation(format!(
                "域名片段 '{}' 格式不合法",
                label
            )));
        }
    }

    Ok(trimmed.to_ascii_lowercase())
}

/// 校验 RFC 1929 用户名与密码约束（单字段 UTF-8 字节长度 1..=255）
pub fn validate_rfc1929_field(field_label: &str, value: &str) -> Result<(), StoreError> {
    let byte_len = value.as_bytes().len();
    if byte_len == 0 {
        return Err(StoreError::Validation(format!(
            "开启认证后{}不能为空",
            field_label
        )));
    }
    if byte_len > 255 {
        return Err(StoreError::Validation(format!(
            "{} UTF-8 字节长度不能超过 255 字节（当前 {} 字节）",
            field_label, byte_len
        )));
    }
    Ok(())
}

/// 快捷粘贴解析：
/// 支持：
/// 1. `socks5://user:pass@host:port`（以及 `socks5://host:port`、IPv6 `[::1]:port`、密码含 `@ : / # %`）
/// 2. `host:port:user:pass`（按前 3 个冒号切分，剩余全部归为 `pass`；兼容 `[ipv6]:port:user:pass` 与无认证 `host:port`）
pub fn parse_proxy_text(raw: &str) -> Result<ParsedProxyDraft, StoreError> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(StoreError::ParseError("粘贴内容为空".to_string()));
    }

    // 分支 A：带协议头 socks5:// 或 socks5h://
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("socks5://") || lower.starts_with("socks5h://") {
        let scheme_len = if lower.starts_with("socks5h://") { 10 } else { 9 };
        let body = text[scheme_len..].trim_end_matches('/');
        if body.is_empty() {
            return Err(StoreError::ParseError("缺少主机与端口信息".to_string()));
        }

        // 从最后一个 `@` 切分认证区与主机区（兼容密码中含 `@ : / # %`）
        if let Some(last_at) = body.rfind('@') {
            let auth_part = &body[..last_at];
            let host_port_part = &body[last_at + 1..];
            let (host, port) = parse_host_and_port(host_port_part)?;

            let Some(first_colon) = auth_part.find(':') else {
                return Err(StoreError::ParseError(
                    "SOCKS5 认证信息缺少密码分隔冒号 (应为 user:pass@host:port)".to_string(),
                ));
            };
            let username = auth_part[..first_colon].trim().to_string();
            let password = auth_part[first_colon + 1..].to_string();
            validate_rfc1929_field("用户名", &username)?;
            validate_rfc1929_field("密码", &password)?;

            return Ok(ParsedProxyDraft {
                host,
                port,
                auth_enabled: true,
                username,
                password,
            });
        } else {
            let (host, port) = parse_host_and_port(body)?;
            return Ok(ParsedProxyDraft {
                host,
                port,
                auth_enabled: false,
                username: String::new(),
                password: String::new(),
            });
        }
    }

    if lower.contains("://") {
        return Err(StoreError::ParseError(
            "仅支持 SOCKS5 协议上游代理（socks5://user:pass@host:port 或 host:port:user:pass）"
                .to_string(),
        ));
    }

    // 分支 B1：以 `[` 开头的 IPv6 行格式：`[ipv6]:port` 或 `[ipv6]:port:user:pass`
    if let Some(after_open) = text.strip_prefix('[') {
        let Some(close_bracket) = after_open.find(']') else {
            return Err(StoreError::ParseError(
                "IPv6 地址缺少闭合右方括号 ']'".to_string(),
            ));
        };
        let ipv6_raw = &after_open[..close_bracket];
        let host = validate_and_normalize_host(&format!("[{}]", ipv6_raw))?;
        let remainder = &after_open[close_bracket + 1..];
        let Some(after_colon) = remainder.strip_prefix(':') else {
            return Err(StoreError::ParseError(
                "IPv6 地址后缺少端口分隔冒号".to_string(),
            ));
        };

        // 切分 port 与可选的 user:pass
        let mut parts = after_colon.splitn(3, ':');
        let port_str = parts.next().unwrap_or("");
        let port = parse_port(port_str)?;

        match (parts.next(), parts.next()) {
            (None, None) => {
                return Ok(ParsedProxyDraft {
                    host,
                    port,
                    auth_enabled: false,
                    username: String::new(),
                    password: String::new(),
                });
            }
            (Some(user_raw), Some(pass_raw)) => {
                let username = user_raw.trim().to_string();
                let password = pass_raw.to_string();
                validate_rfc1929_field("用户名", &username)?;
                validate_rfc1929_field("密码", &password)?;
                return Ok(ParsedProxyDraft {
                    host,
                    port,
                    auth_enabled: true,
                    username,
                    password,
                });
            }
            _ => {
                return Err(StoreError::ParseError(
                    "认证格式不完整，应为 [ipv6]:port:user:pass".to_string(),
                ));
            }
        }
    }

    // 分支 B2：标准 `host:port:user:pass`（严格按前 3 个冒号切分，剩余全部归为 `pass`）或无认证 `host:port`
    let parts: Vec<&str> = text.splitn(4, ':').collect();
    match parts.len() {
        2 => {
            let host = validate_and_normalize_host(parts[0])?;
            let port = parse_port(parts[1])?;
            Ok(ParsedProxyDraft {
                host,
                port,
                auth_enabled: false,
                username: String::new(),
                password: String::new(),
            })
        }
        4 => {
            let host = validate_and_normalize_host(parts[0])?;
            let port = parse_port(parts[1])?;
            let username = parts[2].trim().to_string();
            let password = parts[3].to_string();
            validate_rfc1929_field("用户名", &username)?;
            validate_rfc1929_field("密码", &password)?;
            Ok(ParsedProxyDraft {
                host,
                port,
                auth_enabled: true,
                username,
                password,
            })
        }
        _ => Err(StoreError::ParseError(
            "请使用 host:port:user:pass 或 socks5://user:pass@host:port 格式".to_string(),
        )),
    }
}

fn parse_host_and_port(input: &str) -> Result<(String, u16), StoreError> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') {
        let Some(end_bracket) = trimmed.find(']') else {
            return Err(StoreError::ParseError(
                "IPv6 主机地址缺少右方括号 ']'".to_string(),
            ));
        };
        let host_part = &trimmed[..=end_bracket];
        let rest = &trimmed[end_bracket + 1..];
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err(StoreError::ParseError("缺少端口号 (:port)".to_string()));
        };
        let host = validate_and_normalize_host(host_part)?;
        let port = parse_port(port_str)?;
        Ok((host, port))
    } else {
        let Some(colon_idx) = trimmed.rfind(':') else {
            return Err(StoreError::ParseError("缺少端口号 (:port)".to_string()));
        };
        let host_part = &trimmed[..colon_idx];
        let port_str = &trimmed[colon_idx + 1..];
        if host_part.contains(':') {
            return Err(StoreError::ParseError(
                "IPv6 地址在 URL 中必须使用方括号包裹，例如 [::1]:1080".to_string(),
            ));
        }
        let host = validate_and_normalize_host(host_part)?;
        let port = parse_port(port_str)?;
        Ok((host, port))
    }
}

fn parse_port(raw_port: &str) -> Result<u16, StoreError> {
    let port: u16 = raw_port
        .trim()
        .parse()
        .map_err(|_| StoreError::Validation("端口号必须为 1–65535 之间的整数".to_string()))?;
    if port == 0 {
        return Err(StoreError::Validation(
            "端口号必须为 1–65535 之间的整数".to_string(),
        ));
    }
    Ok(port)
}

/// 线程安全代理配置仓库
pub struct ProxyStore {
    app_data_dir: PathBuf,
    logger: Arc<Logger>,
    state: RwLock<StoreState>,
}

struct StoreState {
    config: AppConfigFile,
    /// 启动加载时是否触发过 `.bak` 备份自动回退（供前端一次性提示用户）
    recovered_from_backup: bool,
}

impl ProxyStore {
    /// 加载或初始化配置仓库（损坏时自动回退 `.bak` 并同步刷新 Logger 脱敏词表）
    pub fn load_or_init(app_data_dir: PathBuf, logger: Arc<Logger>) -> Result<Self, StoreError> {
        fs::create_dir_all(&app_data_dir)?;
        fs::create_dir_all(app_data_dir.join(PROFILES_DIR_NAME))?;

        let config_path = app_data_dir.join(CONFIG_FILE_NAME);
        let backup_path = app_data_dir.join(CONFIG_BACKUP_FILE_NAME);

        let mut recovered_from_backup = false;
        let mut config = if config_path.exists() {
            match Self::read_and_parse(&config_path) {
                Ok(cfg) => cfg,
                Err(primary_err) => {
                    logger.warn(
                        LogKind::App,
                        format!(
                            "主配置文件 config.json 损坏 ({})，尝试从 config.json.bak 自动恢复",
                            primary_err
                        ),
                    );
                    if backup_path.exists() {
                        match Self::read_and_parse(&backup_path) {
                            Ok(bak_cfg) => {
                                recovered_from_backup = true;
                                logger.info(
                                    LogKind::App,
                                    "已成功从 config.json.bak 恢复配置并修复主配置文件",
                                );
                                bak_cfg
                            }
                            Err(bak_err) => {
                                logger.error(
                                    LogKind::App,
                                    format!(
                                        "备份文件 config.json.bak 同样损坏 ({})，按 Fail-Closed 初始化为空配置",
                                        bak_err
                                    ),
                                );
                                AppConfigFile::default()
                            }
                        }
                    } else {
                        logger.error(
                            LogKind::App,
                            "未找到可用的 config.json.bak 备份，按 Fail-Closed 初始化为空配置",
                        );
                        AppConfigFile::default()
                    }
                }
            }
        } else if backup_path.exists() {
            match Self::read_and_parse(&backup_path) {
                Ok(bak_cfg) => {
                    recovered_from_backup = true;
                    logger.info(
                        LogKind::App,
                        "主配置文件缺失，已自动从 config.json.bak 恢复配置",
                    );
                    bak_cfg
                }
                Err(_) => AppConfigFile::default(),
            }
        } else {
            AppConfigFile::default()
        };

        Self::normalize_loaded_config(&mut config);

        let store = Self {
            app_data_dir,
            logger,
            state: RwLock::new(StoreState {
                config,
                recovered_from_backup,
            }),
        };

        // 若从备份恢复，立即原子回写修复主配置文件
        if recovered_from_backup {
            let cfg_clone = store.read_state(|s| s.config.clone());
            let _ = store.persist_atomic(&cfg_clone);
        }

        store.sync_sensitive_rules_to_logger();
        Ok(store)
    }

    fn read_and_parse(path: &Path) -> Result<AppConfigFile, StoreError> {
        let content = fs::read_to_string(path)?;
        let cfg: AppConfigFile = serde_json::from_str(&content)?;
        Ok(cfg)
    }

    /// 修正激活项悬空与非法周期参数
    fn normalize_loaded_config(cfg: &mut AppConfigFile) {
        cfg.schema_version = CONFIG_SCHEMA_VERSION;
        if !WATCHDOG_ALLOWED_INTERVALS.contains(&cfg.settings.watchdog_interval_sec) {
            cfg.settings.watchdog_interval_sec = WATCHDOG_DEFAULT_INTERVAL_SECS;
        }
        if let Some(ref active_id) = cfg.active_proxy_id {
            if !cfg.proxies.iter().any(|p| &p.id == active_id) {
                cfg.active_proxy_id = cfg.proxies.first().map(|p| p.id.clone());
            }
        } else if !cfg.proxies.is_empty() {
            cfg.active_proxy_id = cfg.proxies.first().map(|p| p.id.clone());
        }
    }

    /// 将当前已存代理的用户名与解密密码同步注册到 Logger 脱敏引擎
    fn sync_sensitive_rules_to_logger(&self) {
        let creds: Vec<(String, Option<String>)> = self.read_state(|s| {
            s.config
                .proxies
                .iter()
                .map(|p| {
                    let pwd = if p.password_encrypted.trim().is_empty() {
                        None
                    } else {
                        dpapi_decrypt(&p.password_encrypted).ok()
                    };
                    (p.username.clone(), pwd)
                })
                .collect()
        });
        self.logger.replace_credentials(creds);
    }

    /// 原子持久化：「写临时文件 + sync_all → 有效旧文件备份为 `.bak` → 原子重命名替换」
    fn persist_atomic(&self, cfg: &AppConfigFile) -> Result<(), StoreError> {
        fs::create_dir_all(&self.app_data_dir)?;
        let config_path = self.app_data_dir.join(CONFIG_FILE_NAME);
        let backup_path = self.app_data_dir.join(CONFIG_BACKUP_FILE_NAME);
        let temp_path = self.app_data_dir.join(CONFIG_TEMP_FILE_NAME);

        let serialized = serde_json::to_string_pretty(cfg)?;
        {
            let mut tmp_file = File::create(&temp_path)?;
            tmp_file.write_all(serialized.as_bytes())?;
            tmp_file.sync_all()?;
        }

        // 仅当旧 config.json 存在且本身可合法解析时，才覆盖备份到 config.json.bak
        if config_path.exists() && Self::read_and_parse(&config_path).is_ok() {
            let _ = fs::copy(&config_path, &backup_path);
        }

        fs::rename(&temp_path, &config_path)?;
        Ok(())
    }

    fn read_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&StoreState) -> R,
    {
        let guard = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&guard)
    }

    fn write_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StoreState) -> R,
    {
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    pub fn app_data_dir(&self) -> &Path {
        &self.app_data_dir
    }

    pub fn profiles_dir(&self) -> PathBuf {
        self.app_data_dir.join(PROFILES_DIR_NAME)
    }

    /// 获取某套代理专属的浏览器隔离目录 `%APPDATA%\ClaudeSafeLite\profiles\<proxyId>`
    pub fn profile_dir_for(&self, proxy_id: &str) -> PathBuf {
        self.profiles_dir().join(proxy_id)
    }

    /// 消费「是否从备份自动恢复」标志
    pub fn take_recovered_notice(&self) -> bool {
        self.write_state(|s| {
            let flag = s.recovered_from_backup;
            s.recovered_from_backup = false;
            flag
        })
    }

    /// 列出所有代理的前端安全视图（零密码明文/密文）及当前激活项 ID
    pub fn list_proxies(&self) -> (Vec<ProxyView>, Option<String>) {
        self.read_state(|s| {
            let views = s.config.proxies.iter().map(ProxyView::from).collect();
            (views, s.config.active_proxy_id.clone())
        })
    }

    /// 获取当前全局应用设置
    pub fn get_settings(&self) -> AppSettings {
        self.read_state(|s| s.config.settings.clone())
    }

    /// 更新全局应用设置并原子持久化
    pub fn update_settings(&self, mut new_settings: AppSettings) -> Result<AppSettings, StoreError> {
        new_settings.validate_and_normalize()?;
        let snapshot = self.write_state(|s| {
            s.config.settings = new_settings.clone();
            s.config.clone()
        });
        self.persist_atomic(&snapshot)?;
        Ok(new_settings)
    }

    /// 新增或编辑代理配置（DPAPI 加密失败时直接拒绝保存，严禁明文降级）
    pub fn save_proxy(&self, input: SaveProxyInput) -> Result<ProxyView, StoreError> {
        let name = input.name.trim().to_string();
        if name.is_empty() {
            return Err(StoreError::Validation("配置名称不能为空".to_string()));
        }
        if name.chars().count() > 64 {
            return Err(StoreError::Validation("配置名称不能超过 64 个字符".to_string()));
        }

        let host = validate_and_normalize_host(&input.host)?;
        if input.port == 0 {
            return Err(StoreError::Validation(
                "端口号必须为 1–65535 之间的整数".to_string(),
            ));
        }

        let username = if input.auth_enabled {
            let u = input.username.trim().to_string();
            validate_rfc1929_field("用户名", &u)?;
            u
        } else {
            input.username.trim().to_string()
        };

        // 先将可能输入的新凭据注册到 Logger 防止后续报错泄漏
        self.logger
            .register_transient_credential(&username, input.password.as_deref());

        let (saved_view, snapshot) = self.write_state(|s| -> Result<(ProxyView, AppConfigFile), StoreError> {
            let existing_idx = match input.id.as_deref() {
                Some(id) if !id.trim().is_empty() => {
                    let pos = s
                        .config
                        .proxies
                        .iter()
                        .position(|p| p.id == id)
                        .ok_or(StoreError::ProxyNotFound)?;
                    Some(pos)
                }
                _ => None,
            };

            let password_encrypted = if input.auth_enabled {
                match input.password.as_deref() {
                    Some(plain) if !plain.is_empty() => {
                        validate_rfc1929_field("密码", plain)?;
                        // 调用 Windows DPAPI 加密，失败则立即中断返回错误，绝不落盘明文
                        dpapi_encrypt(plain)?
                    }
                    _ => {
                        // 编辑模式下密码留空：保持原加密密码不变（同时校验原密码有效）
                        if let Some(idx) = existing_idx {
                            let old_enc = &s.config.proxies[idx].password_encrypted;
                            if old_enc.trim().is_empty() {
                                return Err(StoreError::Validation(
                                    "开启认证时必须填写代理密码".to_string(),
                                ));
                            }
                            let _ = dpapi_decrypt(old_enc)?;
                            old_enc.clone()
                        } else {
                            return Err(StoreError::Validation(
                                "新建带认证代理时密码不能为空".to_string(),
                            ));
                        }
                    }
                }
            } else {
                // 未开启认证：若是编辑且未输入新密码，可清空或保留；此处清空避免残留无用凭据
                String::new()
            };

            let view = if let Some(idx) = existing_idx {
                let target = &mut s.config.proxies[idx];
                target.name = name;
                target.host = host;
                target.port = input.port;
                target.auth_enabled = input.auth_enabled;
                target.username = username;
                target.password_encrypted = password_encrypted;
                ProxyView::from(&*target)
            } else {
                let new_id = Uuid::new_v4().to_string();
                let record = StoredProxy {
                    id: new_id.clone(),
                    name,
                    host,
                    port: input.port,
                    auth_enabled: input.auth_enabled,
                    username,
                    password_encrypted,
                };
                let view = ProxyView::from(&record);
                s.config.proxies.push(record);
                if s.config.active_proxy_id.is_none() {
                    s.config.active_proxy_id = Some(new_id);
                }
                view
            };

            Ok((view, s.config.clone()))
        })?;

        self.persist_atomic(&snapshot)?;
        self.sync_sensitive_rules_to_logger();
        Ok(saved_view)
    }

    /// 复制已有代理配置（保留原加密密码，无需前端经手明文）
    pub fn duplicate_proxy(&self, id: &str) -> Result<ProxyView, StoreError> {
        let (view, snapshot) = self.write_state(|s| -> Result<(ProxyView, AppConfigFile), StoreError> {
            let source = s
                .config
                .proxies
                .iter()
                .find(|p| p.id == id)
                .ok_or(StoreError::ProxyNotFound)?
                .clone();

            let mut copy_name = format!("{} - 副本", source.name);
            if copy_name.chars().count() > 64 {
                copy_name = copy_name.chars().take(64).collect();
            }

            let duplicated = StoredProxy {
                id: Uuid::new_v4().to_string(),
                name: copy_name,
                host: source.host,
                port: source.port,
                auth_enabled: source.auth_enabled,
                username: source.username,
                password_encrypted: source.password_encrypted,
            };
            let view = ProxyView::from(&duplicated);
            s.config.proxies.push(duplicated);
            Ok((view, s.config.clone()))
        })?;

        self.persist_atomic(&snapshot)?;
        Ok(view)
    }

    /// 删除代理配置（删除当前激活项时自动切换至列表第一项，列表为空时置为 `None`）
    pub fn delete_proxy(&self, id: &str) -> Result<Option<String>, StoreError> {
        let (new_active, snapshot) =
            self.write_state(|s| -> Result<(Option<String>, AppConfigFile), StoreError> {
                let pos = s
                    .config
                    .proxies
                    .iter()
                    .position(|p| p.id == id)
                    .ok_or(StoreError::ProxyNotFound)?;
                s.config.proxies.remove(pos);

                if s.config.active_proxy_id.as_deref() == Some(id) {
                    s.config.active_proxy_id = s.config.proxies.first().map(|p| p.id.clone());
                }
                Ok((s.config.active_proxy_id.clone(), s.config.clone()))
            })?;

        self.persist_atomic(&snapshot)?;
        self.sync_sensitive_rules_to_logger();
        Ok(new_active)
    }

    /// 切换当前激活的代理配置
    pub fn set_active_proxy(&self, id: &str) -> Result<ProxyView, StoreError> {
        let (view, snapshot) = self.write_state(|s| -> Result<(ProxyView, AppConfigFile), StoreError> {
            let target = s
                .config
                .proxies
                .iter()
                .find(|p| p.id == id)
                .ok_or(StoreError::ProxyNotFound)?;
            let view = ProxyView::from(target);
            s.config.active_proxy_id = Some(id.to_string());
            Ok((view, s.config.clone()))
        })?;

        self.persist_atomic(&snapshot)?;
        Ok(view)
    }

    /// 获取当前激活代理的后端解密连接参数（仅供内部 Forwarder / Checker 瞬时读取）
    pub fn resolve_active_upstream(&self) -> Result<Option<ResolvedUpstreamProxy>, StoreError> {
        let active_opt = self.read_state(|s| {
            let active_id = s.config.active_proxy_id.as_ref()?;
            s.config
                .proxies
                .iter()
                .find(|p| &p.id == active_id)
                .cloned()
        });

        match active_opt {
            None => Ok(None),
            Some(sp) => Ok(Some(Self::decrypt_stored_proxy(&sp)?)),
        }
    }

    /// 根据表单临时输入（包含「编辑态留空复用原加密密码」场景）解析出单次测试用上游连接参数
    pub fn resolve_transient_upstream(
        &self,
        input: &SaveProxyInput,
    ) -> Result<ResolvedUpstreamProxy, StoreError> {
        let host = validate_and_normalize_host(&input.host)?;
        if input.port == 0 {
            return Err(StoreError::Validation(
                "端口号必须为 1–65535 之间的整数".to_string(),
            ));
        }

        let auth = if input.auth_enabled {
            let username = input.username.trim().to_string();
            validate_rfc1929_field("用户名", &username)?;

            let password = match input.password.as_deref() {
                Some(p) if !p.is_empty() => {
                    validate_rfc1929_field("密码", p)?;
                    p.to_string()
                }
                _ => {
                    if let Some(ref existing_id) = input.id {
                        let enc = self.read_state(|s| {
                            s.config
                                .proxies
                                .iter()
                                .find(|p| &p.id == existing_id)
                                .map(|p| p.password_encrypted.clone())
                        });
                        match enc {
                            Some(e) if !e.trim().is_empty() => dpapi_decrypt(&e)?,
                            _ => {
                                return Err(StoreError::Validation(
                                    "请填写代理密码后再测试连接".to_string(),
                                ))
                            }
                        }
                    } else {
                        return Err(StoreError::Validation(
                            "请填写代理密码后再测试连接".to_string(),
                        ));
                    }
                }
            };

            self.logger
                .register_transient_credential(&username, Some(&password));
            Some((username, password))
        } else {
            None
        };

        Ok(ResolvedUpstreamProxy {
            id: input
                .id
                .clone()
                .unwrap_or_else(|| "transient-test".to_string()),
            name: if input.name.trim().is_empty() {
                "临时测试节点".to_string()
            } else {
                input.name.trim().to_string()
            },
            host,
            port: input.port,
            auth,
        })
    }

    fn decrypt_stored_proxy(sp: &StoredProxy) -> Result<ResolvedUpstreamProxy, StoreError> {
        let auth = if sp.auth_enabled {
            let pwd = dpapi_decrypt(&sp.password_encrypted)?;
            Some((sp.username.clone(), pwd))
        } else {
            None
        };
        Ok(ResolvedUpstreamProxy {
            id: sp.id.clone(),
            name: sp.name.clone(),
            host: sp.host.clone(),
            port: sp.port,
            auth,
        })
    }

    /// 供「重置环境」按需清空代理或恢复默认设置
    pub fn reset_store(
        &self,
        clear_all_proxies: bool,
        restore_default_settings: bool,
    ) -> Result<(), StoreError> {
        let snapshot = self.write_state(|s| {
            if clear_all_proxies {
                s.config.proxies.clear();
                s.config.active_proxy_id = None;
            }
            if restore_default_settings {
                s.config.settings = AppSettings::default();
            }
            s.config.clone()
        });

        self.persist_atomic(&snapshot)?;
        self.sync_sensitive_rules_to_logger();
        Ok(())
    }

    /// 读取本机已解密的授权载荷（供启动后台向云端心跳核验使用）
    pub fn get_stored_license_payload(&self) -> Option<StoredLicensePayload> {
        let enc = self.read_state(|s| s.config.license_encrypted.clone())?;
        if enc.trim().is_empty() {
            return None;
        }
        let json = dpapi_decrypt(&enc).ok()?;
        serde_json::from_str::<StoredLicensePayload>(&json).ok()
    }

    /// 读取并实时复验当前保存的本机授权状态（DPAPI 解密 + Ed25519 验签 + 机器码比对 + 到期时间检查）
    pub fn get_license_status(&self) -> LicenseStatusView {
        let Some(stored) = self.get_stored_license_payload() else {
            return LicenseStatusView::unauthorized_default(None, None, None);
        };

        match verify_signed_ticket(
            &stored.code,
            &stored.machine_code,
            &stored.expires_at,
            stored.issued_unix,
            &stored.signature_hex,
        ) {
            Ok((is_permanent, days_remaining)) => LicenseStatusView {
                authorized: true,
                machine_code: get_machine_code(),
                holder_name: Some(stored.name),
                holder_phone: Some(stored.phone),
                is_permanent,
                expires_at: Some(stored.expires_at),
                days_remaining,
                machine_bound: true,
                expired_message: None,
            },
            Err(LicenseError::Expired(exp_date)) => LicenseStatusView::unauthorized_default(
                Some(stored.name),
                Some(stored.phone),
                Some(format!(
                    "您的软件授权已于 {} 到期 → 请联系管理员获取新的续期授权码",
                    exp_date
                )),
            ),
            Err(_) => LicenseStatusView::unauthorized_default(
                Some(stored.name),
                Some(stored.phone),
                None,
            ),
        }
    }

    /// 后端强门禁：核心命令执行前实时校验授权有效性
    pub fn ensure_authorized(&self) -> Result<(), StoreError> {
        let status = self.get_license_status();
        if status.authorized {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }

    /// 保存已通过云端核验与 Ed25519 验签的授权通行证（通过 Windows DPAPI 加密持久化）
    pub fn save_verified_license(
        &self,
        payload: &StoredLicensePayload,
    ) -> Result<LicenseStatusView, StoreError> {
        let (is_permanent, days_remaining) = verify_signed_ticket(
            &payload.code,
            &payload.machine_code,
            &payload.expires_at,
            payload.issued_unix,
            &payload.signature_hex,
        )?;

        let json_str = serde_json::to_string(payload)?;
        let encrypted = dpapi_encrypt(&json_str)?;

        let snapshot = self.write_state(|s| {
            s.config.license_encrypted = Some(encrypted);
            s.config.clone()
        });
        self.persist_atomic(&snapshot)?;

        Ok(LicenseStatusView {
            authorized: true,
            machine_code: get_machine_code(),
            holder_name: Some(payload.name.clone()),
            holder_phone: Some(payload.phone.clone()),
            is_permanent,
            expires_at: Some(payload.expires_at.clone()),
            days_remaining,
            machine_bound: true,
            expired_message: None,
        })
    }

    /// 退出/吊销当前本机授权状态
    pub fn clear_license_with_reason(
        &self,
        reason: Option<String>,
    ) -> Result<LicenseStatusView, StoreError> {
        let prev = self.get_stored_license_payload();
        let snapshot = self.write_state(|s| {
            s.config.license_encrypted = None;
            s.config.clone()
        });
        self.persist_atomic(&snapshot)?;

        Ok(LicenseStatusView::unauthorized_default(
            prev.as_ref().map(|p| p.name.clone()),
            prev.as_ref().map(|p| p.phone.clone()),
            reason,
        ))
    }
}

