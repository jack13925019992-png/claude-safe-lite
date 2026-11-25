//! 分类脱敏轮转日志模块（Logger）
//!
//! 严格遵循安全红线：
//! 1. 任何日志、界面、错误提示中严禁出现代理密码明文；
//! 2. 代理用户名在日志中仅显示前 2 位 + `***`（不足 2 位显示 `***`）；
//! 3. 支持 `app.log` / `check.log` / `launch.log` 三分类，单文件上限 5MB，保留最近 3 份（`.1` `.2` `.3`）。

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::constants::{
    LOGS_DIR_NAME, LOG_DEFAULT_TAIL_LINES, LOG_MAX_BYTES, LOG_MAX_ROTATED_FILES,
};

/// 日志分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogKind {
    /// 应用与熔断日志 (`app.log`)
    App,
    /// 五项检测与巡检日志 (`check.log`)
    Check,
    /// 浏览器/工具启动与退出日志 (`launch.log`)
    Launch,
}

impl LogKind {
    pub fn file_name(self) -> &'static str {
        match self {
            LogKind::App => "app.log",
            LogKind::Check => "check.log",
            LogKind::Launch => "launch.log",
        }
    }
}

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// 对代理用户名执行脱敏：
/// 长度 >= 2 个字符时保留前 2 个字符 + `***`；不足 2 位一律返回 `***`。
pub fn mask_username(username: &str) -> String {
    let trimmed = username.trim();
    let mut chars = trimmed.chars();
    match (chars.next(), chars.next()) {
        (Some(c1), Some(c2)) => format!("{}{}***", c1, c2),
        _ => "***".to_string(),
    }
}

/// 生成字符串的 URL 百分号编码形式（用于同时拦截被 URL 编码后的密码泄漏）
fn percent_encode_all_special(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// 内存敏感词表（仅用于写出与报错前脱敏替换）
#[derive(Default)]
struct SensitiveRules {
    /// 需要被替换为 `[已脱敏密码]` 的密码变体（按长度降序排列）
    passwords: Vec<String>,
    /// 需要被替换为脱敏形式的 `(原始用户名, 脱敏后用户名)`（按长度降序排列）
    usernames: Vec<(String, String)>,
}

/// 线程安全分类日志管理器
pub struct Logger {
    logs_dir: PathBuf,
    max_file_bytes: u64,
    write_lock: std::sync::Mutex<()>,
    rules: RwLock<SensitiveRules>,
}

impl Logger {
    /// 使用应用数据根目录创建 Logger（日志位于 `<app_data_dir>/logs/`）
    pub fn new(app_data_dir: &Path) -> std::io::Result<Self> {
        Self::with_max_bytes(app_data_dir, LOG_MAX_BYTES)
    }

    /// 指定单文件最大字节数创建 Logger（便于单元测试验证轮转）
    pub fn with_max_bytes(app_data_dir: &Path, max_file_bytes: u64) -> std::io::Result<Self> {
        let logs_dir = app_data_dir.join(LOGS_DIR_NAME);
        fs::create_dir_all(&logs_dir)?;
        Ok(Self {
            logs_dir,
            max_file_bytes,
            write_lock: std::sync::Mutex::new(()),
            rules: RwLock::new(SensitiveRules::default()),
        })
    }

    /// 获取日志目录路径
    pub fn logs_dir(&self) -> &Path {
        &self.logs_dir
    }

    /// 获取指定分类主日志文件的完整路径
    pub fn log_file_path(&self, kind: LogKind) -> PathBuf {
        self.logs_dir.join(kind.file_name())
    }

    /// 全量刷新当前已知的敏感凭据集合（例如在配置加载、保存后调用）
    pub fn replace_credentials<I>(&self, creds: I)
    where
        I: IntoIterator<Item = (String, Option<String>)>,
    {
        let mut passwords: Vec<String> = Vec::new();
        let mut usernames: Vec<(String, String)> = Vec::new();

        for (user, pass_opt) in creds {
            Self::collect_credential(&mut usernames, &mut passwords, &user, pass_opt.as_deref());
        }

        Self::sort_and_dedup(&mut usernames, &mut passwords);

        if let Ok(mut guard) = self.rules.write() {
            guard.passwords = passwords;
            guard.usernames = usernames;
        }
    }

    /// 增量注册单组临时凭据（例如用户在编辑框内点击「测试连接」尚未保存时，也必须保护其密码不落盘）
    pub fn register_transient_credential(&self, username: &str, password: Option<&str>) {
        if let Ok(mut guard) = self.rules.write() {
            let rules = &mut *guard;
            Self::collect_credential(
                &mut rules.usernames,
                &mut rules.passwords,
                username,
                password,
            );
            Self::sort_and_dedup(&mut rules.usernames, &mut rules.passwords);
        }
    }

    fn collect_credential(
        usernames: &mut Vec<(String, String)>,
        passwords: &mut Vec<String>,
        user: &str,
        pass_opt: Option<&str>,
    ) {
        let trimmed_user = user.trim();
        if !trimmed_user.is_empty() {
            let masked = mask_username(trimmed_user);
            usernames.push((trimmed_user.to_string(), masked.clone()));
            let encoded_user = percent_encode_all_special(trimmed_user);
            if encoded_user != trimmed_user {
                let lower_user = encoded_user.to_ascii_lowercase();
                usernames.push((encoded_user, masked.clone()));
                usernames.push((lower_user, masked));
            }
        }

        if let Some(p) = pass_opt {
            if !p.is_empty() {
                passwords.push(p.to_string());
                let encoded = percent_encode_all_special(p);
                if encoded != p {
                    passwords.push(encoded.clone());
                    passwords.push(encoded.to_ascii_lowercase());
                }
            }
        }
    }

    fn sort_and_dedup(usernames: &mut Vec<(String, String)>, passwords: &mut Vec<String>) {
        passwords.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        passwords.dedup();

        usernames.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        usernames.dedup_by(|a, b| a.0 == b.0);
    }

    /// 对任意文本执行强制脱敏（可用于日志写入、界面错误提示与导出）
    pub fn sanitize(&self, input: &str) -> String {
        // 第一层：抹除内联 URL 凭据（如 socks5://user:pass@host:port），防止未注册的原始粘贴内容泄漏
        let mut text = redact_inline_url_credentials(input);

        // 第二层：按已注册密码与用户名词表强替换（密码优先于用户名）
        if let Ok(guard) = self.rules.read() {
            for pwd in &guard.passwords {
                if !pwd.is_empty() && text.contains(pwd) {
                    text = text.replace(pwd, "[REDACTED]");
                }
            }
            for (raw_user, masked_user) in &guard.usernames {
                if !raw_user.is_empty() && text.contains(raw_user) {
                    text = text.replace(raw_user, masked_user);
                }
            }
        }

        text
    }

    /// 写入一条日志记录（自动附加本地时间戳、级别、脱敏与 5MB 轮转）
    pub fn log(&self, kind: LogKind, level: LogLevel, message: &str) {
        let _ = self.try_log(kind, level, message);
    }

    pub fn info(&self, kind: LogKind, message: impl AsRef<str>) {
        self.log(kind, LogLevel::Info, message.as_ref());
    }

    pub fn warn(&self, kind: LogKind, message: impl AsRef<str>) {
        self.log(kind, LogLevel::Warn, message.as_ref());
    }

    pub fn error(&self, kind: LogKind, message: impl AsRef<str>) {
        self.log(kind, LogLevel::Error, message.as_ref());
    }

    /// 写入日志并返回可能的 I/O 错误
    pub fn try_log(&self, kind: LogKind, level: LogLevel, message: &str) -> std::io::Result<()> {
        let sanitized_msg = self.sanitize(message).replace('\r', " ").replace('\n', " | ");
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!("[{}] [{}] {}\n", timestamp, level.as_str(), sanitized_msg);
        let line_bytes = line.as_bytes();

        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        fs::create_dir_all(&self.logs_dir)?;
        let file_path = self.log_file_path(kind);

        self.rotate_if_needed(&file_path, line_bytes.len() as u64)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        file.write_all(line_bytes)?;
        file.flush()?;
        Ok(())
    }

    /// 检查当前文件大小，若写入后超过 `max_file_bytes`，滚动保留 `.1` `.2` `.3`
    fn rotate_if_needed(&self, base_path: &Path, incoming_bytes: u64) -> std::io::Result<()> {
        let current_len = match fs::metadata(base_path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        if current_len == 0 || current_len.saturating_add(incoming_bytes) <= self.max_file_bytes {
            return Ok(());
        }

        // 删除最旧的分片 .3
        let oldest = Self::rotated_path(base_path, LOG_MAX_ROTATED_FILES);
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }

        // 依次向后滚动：.2 -> .3, .1 -> .2
        for idx in (1..LOG_MAX_ROTATED_FILES).rev() {
            let src = Self::rotated_path(base_path, idx);
            let dst = Self::rotated_path(base_path, idx + 1);
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        // 当前主文件 -> .1
        let first_rot = Self::rotated_path(base_path, 1);
        fs::rename(base_path, first_rot)?;
        Ok(())
    }

    /// 获取第 `index` 个轮转分片的路径（例如 `app.log.1`）
    pub fn rotated_path(base_path: &Path, index: usize) -> PathBuf {
        let mut os = base_path.as_os_str().to_os_string();
        os.push(format!(".{}", index));
        PathBuf::from(os)
    }

    /// 读取指定分类最近 `max_lines` 行日志（默认 500 行；若刚发生轮转，自动从 `.1` 补齐）
    pub fn read_tail(&self, kind: LogKind, max_lines: Option<usize>) -> std::io::Result<Vec<String>> {
        let limit = max_lines.unwrap_or(LOG_DEFAULT_TAIL_LINES).max(1);
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let base_path = self.log_file_path(kind);
        let mut ring: VecDeque<String> = VecDeque::with_capacity(limit.min(1024));

        // 先读 .1（若存在），再读当前文件，确保刚轮转后界面依然有连续上下文
        let rot1 = Self::rotated_path(&base_path, 1);
        if rot1.exists() {
            Self::push_file_lines(&rot1, &mut ring, limit)?;
        }
        if base_path.exists() {
            Self::push_file_lines(&base_path, &mut ring, limit)?;
        }

        // 读取时再做一次 sanitize 兜底保障零明文
        Ok(ring.into_iter().map(|line| self.sanitize(&line)).collect())
    }

    fn push_file_lines(
        path: &Path,
        ring: &mut VecDeque<String>,
        limit: usize,
    ) -> std::io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let line = line_res?;
            if ring.len() == limit {
                ring.pop_front();
            }
            ring.push_back(line);
        }
        Ok(())
    }

    /// 清空指定分类的当前日志及所有轮转分片
    pub fn clear(&self, kind: LogKind) -> std::io::Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let base_path = self.log_file_path(kind);
        if base_path.exists() {
            fs::remove_file(&base_path)?;
        }
        for idx in 1..=LOG_MAX_ROTATED_FILES {
            let rot = Self::rotated_path(&base_path, idx);
            if rot.exists() {
                let _ = fs::remove_file(&rot);
            }
        }
        Ok(())
    }

    /// 清空全部三类日志（供「重置环境」调用）
    pub fn clear_all(&self) -> std::io::Result<()> {
        self.clear(LogKind::App)?;
        self.clear(LogKind::Check)?;
        self.clear(LogKind::Launch)?;
        Ok(())
    }

    /// 将指定分类日志（按时间顺序合并历史轮转分片与当前文件）脱敏导出到目标路径
    pub fn export_to(&self, kind: LogKind, dest_path: &Path) -> std::io::Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(parent) = dest_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let mut out = File::create(dest_path)?;
        let base_path = self.log_file_path(kind);

        for idx in (1..=LOG_MAX_ROTATED_FILES).rev() {
            let rot = Self::rotated_path(&base_path, idx);
            if rot.exists() {
                self.copy_sanitized_lines(&rot, &mut out)?;
            }
        }
        if base_path.exists() {
            self.copy_sanitized_lines(&base_path, &mut out)?;
        }
        out.flush()?;
        Ok(())
    }

    fn copy_sanitized_lines(&self, src: &Path, out: &mut File) -> std::io::Result<()> {
        let file = File::open(src)?;
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let line = self.sanitize(&line_res?);
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
        }
        Ok(())
    }
}

/// 扫描文本中的内联协议凭据（如 `socks5://user:pass@host:port`），自动脱敏用户名与密码
fn redact_inline_url_credentials(input: &str) -> String {
    const SCHEMES: &[&str] = &["socks5://", "socks5h://", "http://", "https://"];
    let mut result = String::with_capacity(input.len());
    let mut rest = input;

    while !rest.is_empty() {
        // 查找最早出现的 scheme
        let mut earliest: Option<(usize, &str)> = None;
        for &scheme in SCHEMES {
            if let Some(pos) = rest.find(scheme) {
                match earliest {
                    None => earliest = Some((pos, scheme)),
                    Some((cur_pos, _)) if pos < cur_pos => earliest = Some((pos, scheme)),
                    _ => {}
                }
            }
        }

        let Some((scheme_pos, scheme)) = earliest else {
            result.push_str(rest);
            break;
        };

        // 输出 scheme 及其之前的内容
        let after_scheme_idx = scheme_pos + scheme.len();
        result.push_str(&rest[..after_scheme_idx]);
        let after_scheme = &rest[after_scheme_idx..];

        // 截取当前 URL token（遇到空白字符、引号或右括号结束）
        let token_end = after_scheme
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | ']'))
            .unwrap_or(after_scheme.len());

        // 注意 IPv6 地址如 socks5://user:pass@[::1]:1080 中含 ']'，特判 '[' 存在时扩展到对应 ']' 之后
        let token_end = if after_scheme[..token_end].contains('[') || after_scheme.contains('@') {
            after_scheme
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>'))
                .unwrap_or(after_scheme.len())
        } else {
            token_end
        };

        let url_body = &after_scheme[..token_end];
        // 限定在 path `/` 之前的 authority 区查找最后一个 `@`
        // 注意：若密码本身含 `/`，在代理串如 socks5://u:p/1@1.2.3.4:1080 中 `@` 在 `/` 后，
        // 因此只要整个 url_body 中 `@` 后面紧跟合法 host:port 结构，就按最后一个 `@` 切分
        if let Some(at_pos) = url_body.rfind('@') {
            let auth_part = &url_body[..at_pos];
            let host_and_rest = &url_body[at_pos + 1..];
            if let Some(colon_pos) = auth_part.find(':') {
                let user = &auth_part[..colon_pos];
                result.push_str(&mask_username(user));
                result.push_str(":[REDACTED]@");
                result.push_str(host_and_rest);
            } else {
                result.push_str(&mask_username(auth_part));
                result.push('@');
                result.push_str(host_and_rest);
            }
        } else {
            result.push_str(url_body);
        }

        rest = &after_scheme[token_end..];
    }

    result
}

