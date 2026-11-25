//! 统一友好报错规范模块（需求文档 6.2）
//!
//! 所有呈现给用户的报错统一采用：「人话原因 + 建议动作 + 折叠技术细节（强制脱敏）」结构。

use serde::{Deserialize, Serialize};

use crate::logger::Logger;
use crate::socks5::UpstreamError;

/// 结构化友好错误（供前端直接展示人话文案与折叠技术详情）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HumanizedError {
    /// 错误分类编码
    pub code: String,
    /// 界面主展示文案（人话原因 → 建议动作）
    pub user_message: String,
    /// 折叠技术细节（已强制通过 Logger 脱敏，零明文密码）
    pub technical_detail: String,
}

impl HumanizedError {
    pub fn new(
        code: impl Into<String>,
        user_message: impl Into<String>,
        raw_detail: impl AsRef<str>,
        logger: Option<&Logger>,
    ) -> Self {
        let detail = match logger {
            Some(l) => l.sanitize(raw_detail.as_ref()),
            None => raw_detail.as_ref().to_string(),
        };
        Self {
            code: code.into(),
            user_message: user_message.into(),
            technical_detail: detail,
        }
    }

    /// 将上游 SOCKS5 错误转换为需求文档 6.2 标准人话文案
    pub fn from_upstream_error(err: &UpstreamError, logger: Option<&Logger>) -> Self {
        match err {
            UpstreamError::ConnectTimeout => Self::new(
                "UPSTREAM_TIMEOUT",
                "代理响应超时 → 可能是网络波动或节点繁忙，请稍后重试或更换节点",
                err.to_string(),
                logger,
            ),
            UpstreamError::AuthRejected(_) => Self::new(
                "UPSTREAM_AUTH_FAILED",
                "代理账号或密码被拒绝 → 请核对用户名与密码（注意大小写与特殊字符）",
                err.to_string(),
                logger,
            ),
            UpstreamError::ProxyUnreachable(_) => Self::new(
                "UPSTREAM_UNREACHABLE",
                "代理连不上 → 请检查代理地址、端口是否正确，以及上游服务是否在线",
                err.to_string(),
                logger,
            ),
            UpstreamError::TargetRejected { rep, .. } => Self::new(
                "UPSTREAM_REJECTED",
                format!(
                    "上游代理拒绝了连接请求 (SOCKS5 码 0x{:02X}) → 请检查代理节点权限或更换节点",
                    rep
                ),
                err.to_string(),
                logger,
            ),
            UpstreamError::ProtocolViolation(_) | UpstreamError::InvalidTarget(_) => Self::new(
                "UPSTREAM_PROTOCOL_ERROR",
                "代理协议握手异常 → 请确认该节点为标准 SOCKS5 代理而非 HTTP 代理",
                err.to_string(),
                logger,
            ),
        }
    }

    pub fn claude_forbidden(status_or_reason: &str, logger: Option<&Logger>) -> Self {
        Self::new(
            "CLAUDE_BLOCKED",
            "当前出口 IP 可能被识别为机房/高风险 IP，遭 Claude 拦截，建议更换静态住宅 IP",
            status_or_reason,
            logger,
        )
    }

    pub fn low_ip_reputation(detail: &str, logger: Option<&Logger>) -> Self {
        Self::new(
            "IP_RISK_WARN",
            "当前出口 IP 风评偏低，存在封号/风控隐患，建议更换更纯净的静态 IP",
            detail,
            logger,
        )
    }

    pub fn browser_not_found() -> Self {
        let detail = if cfg!(target_os = "macos") {
            "Standard macOS /Applications & Spotlight did not match Brave Browser.app or Google Chrome.app"
        } else {
            "Registry App Paths & standard installation paths did not match brave.exe or chrome.exe"
        };
        Self::new(
            "BROWSER_NOT_FOUND",
            "未检测到 Brave 或 Chrome → 请点击下载安装 Brave，或在设置中手动指定浏览器路径",
            detail,
            None,
        )
    }

    pub fn profile_in_use(proxy_name: &str) -> Self {
        Self::new(
            "PROFILE_LOCKED",
            "该代理配置的安全浏览器已在运行，请先关闭后再试",
            format!("Profile lock active for proxy: {}", proxy_name),
            None,
        )
    }

    pub fn forwarder_bind_failed(raw_err: &str, logger: Option<&Logger>) -> Self {
        Self::new(
            "FORWARDER_BIND_FAILED",
            "本地回环端口绑定失败（可能被安全软件拦截），请重试或检查杀软放行",
            raw_err,
            logger,
        )
    }

    pub fn leak_circuit_tripped(detail: &str, logger: Option<&Logger>) -> Self {
        Self::new(
            "TRIPPED_LEAK",
            "检测到 IP/DNS 泄露，已强制关闭安全浏览器并停止转发 → 请检查本地网络/代理状态，点击「重新检测」通过后再启动",
            detail,
            logger,
        )
    }

    pub fn disconnect_circuit_tripped(detail: &str, logger: Option<&Logger>) -> Self {
        Self::new(
            "TRIPPED_DISCONNECT",
            "代理连接中途断开，为防流量直连裸奔已关闭浏览器 → 请确认代理节点恢复后，点击「重新检测」解锁",
            detail,
            logger,
        )
    }
}
