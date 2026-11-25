//! 上游 SOCKS5 客户端与 RFC 1929 认证核心模块
//!
//! 核心约束（需求文档 4.1 & 7.1）：
//! 1. 全工程唯一标准上游 SOCKS5 握手与 RFC 1929 认证实现；
//! 2. 收到域名类型（`0x03`）时原样透传给上游代理，严禁在本地执行目标站点 DNS 解析；
//! 3. RFC 1929 用户名与密码长度字节严格按 UTF-8 `as_bytes().len()` 计算（1..=255）；
//! 4. 上游建连与握手总超时 10 秒，精准区分「无法连接 / 超时 / 认证失败 / 协议错误 / 目标站点拒连」。

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::constants::UPSTREAM_CONNECT_TIMEOUT_SECS;
use crate::proxy_store::ResolvedUpstreamProxy;

pub const SOCKS5_VERSION: u8 = 0x05;
pub const AUTH_METHOD_NONE: u8 = 0x00;
pub const AUTH_METHOD_USERPASS: u8 = 0x02;
pub const AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xFF;
pub const RFC1929_VERSION: u8 = 0x01;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// 代理转发的目标地址（严格保留域名形态以实现透传）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ipv4(Ipv4Addr, u16),
    Domain(String, u16),
    Ipv6(Ipv6Addr, u16),
}

impl TargetAddr {
    /// 从主机字符串与端口构造 `TargetAddr`（若非字面量 IPv4/IPv6，一律保留为 `Domain` 原样透传）
    pub fn from_host_port(raw_host: &str, port: u16) -> Result<Self, UpstreamError> {
        let trimmed = raw_host.trim();
        if trimmed.is_empty() || port == 0 {
            return Err(UpstreamError::InvalidTarget(
                "目标主机为空或端口为 0".to_string(),
            ));
        }

        let unbracketed = trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(trimmed);

        if let Ok(v4) = unbracketed.parse::<Ipv4Addr>() {
            return Ok(TargetAddr::Ipv4(v4, port));
        }
        if let Ok(v6) = unbracketed.parse::<Ipv6Addr>() {
            return Ok(TargetAddr::Ipv6(v6, port));
        }

        let domain_bytes = unbracketed.as_bytes();
        if domain_bytes.is_empty() || domain_bytes.len() > 255 {
            return Err(UpstreamError::InvalidTarget(format!(
                "目标域名长度不合法 ({} 字节)",
                domain_bytes.len()
            )));
        }
        if unbracketed.chars().any(char::is_whitespace) {
            return Err(UpstreamError::InvalidTarget(
                "目标域名包含空白字符".to_string(),
            ));
        }

        Ok(TargetAddr::Domain(unbracketed.to_string(), port))
    }

    pub fn display_endpoint(&self) -> String {
        match self {
            TargetAddr::Ipv4(ip, port) => format!("{}:{}", ip, port),
            TargetAddr::Domain(host, port) => format!("{}:{}", host, port),
            TargetAddr::Ipv6(ip, port) => format!("[{}]:{}", ip, port),
        }
    }
}

/// 上游 SOCKS5 建连与握手精细错误枚举（注意：严禁在任何变体中携带明文密码）
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum UpstreamError {
    #[error("无法连接到上游代理服务器: {0}")]
    ProxyUnreachable(String),

    #[error("连接上游代理服务器握手超时")]
    ConnectTimeout,

    #[error("上游代理拒绝认证: {0}")]
    AuthRejected(String),

    #[error("上游代理协议响应非法: {0}")]
    ProtocolViolation(String),

    #[error("上游代理未能连接目标站点 (SOCKS5 REP=0x{rep:02X}: {description})")]
    TargetRejected { rep: u8, description: String },

    #[error("非法的转发目标地址: {0}")]
    InvalidTarget(String),
}

impl UpstreamError {
    /// 向下游 SOCKS5 客户端返回的规范错误应答码
    pub fn to_socks5_rep(&self) -> u8 {
        match self {
            UpstreamError::ProxyUnreachable(_) => REP_GENERAL_FAILURE,
            UpstreamError::ConnectTimeout => REP_HOST_UNREACHABLE,
            UpstreamError::AuthRejected(_) => REP_CONNECTION_NOT_ALLOWED,
            UpstreamError::ProtocolViolation(_) => REP_GENERAL_FAILURE,
            UpstreamError::TargetRejected { rep, .. } => {
                if *rep == REP_SUCCEEDED {
                    REP_GENERAL_FAILURE
                } else {
                    *rep
                }
            }
            UpstreamError::InvalidTarget(_) => REP_ADDR_TYPE_NOT_SUPPORTED,
        }
    }

    /// 是否属于「上游代理自身不可用/掉线/认证失效」故障（用于联动 Watchdog 连续失败计数，排除目标网站自身拒连）
    pub fn is_upstream_fault(&self) -> bool {
        match self {
            UpstreamError::ProxyUnreachable(_)
            | UpstreamError::ConnectTimeout
            | UpstreamError::AuthRejected(_)
            | UpstreamError::ProtocolViolation(_) => true,
            UpstreamError::TargetRejected { rep, .. } => {
                // 0x01 General SOCKS server failure 属于代理服务端故障；
                // 0x04/0x05 等表示已通过认证但目标站点本身拒连或不可达，不误判为代理掉线
                *rep == REP_GENERAL_FAILURE || *rep == REP_CONNECTION_NOT_ALLOWED
            }
            UpstreamError::InvalidTarget(_) => false,
        }
    }

    /// 用于 01 项检测结果的简短分类标签
    pub fn short_category(&self) -> &'static str {
        match self {
            UpstreamError::ProxyUnreachable(_) => "无法连接",
            UpstreamError::ConnectTimeout => "连接超时",
            UpstreamError::AuthRejected(_) => "认证失败",
            UpstreamError::TargetRejected { .. } => "上游拒绝",
            UpstreamError::ProtocolViolation(_) | UpstreamError::InvalidTarget(_) => "协议异常",
        }
    }
}

pub fn describe_socks5_rep(rep: u8) -> &'static str {
    match rep {
        REP_SUCCEEDED => "成功",
        REP_GENERAL_FAILURE => "代理服务器内部故障",
        REP_CONNECTION_NOT_ALLOWED => "代理规则禁止连接",
        REP_NETWORK_UNREACHABLE => "目标网络不可达",
        REP_HOST_UNREACHABLE => "目标主机不可达",
        REP_CONNECTION_REFUSED => "目标站点拒绝连接",
        REP_TTL_EXPIRED => "TTL 超时",
        REP_COMMAND_NOT_SUPPORTED => "不支持的 SOCKS5 命令",
        REP_ADDR_TYPE_NOT_SUPPORTED => "不支持的地址类型",
        _ => "未知错误码",
    }
}

/// 构造 RFC 1929 用户名/密码认证报文：
/// `[0x01, ULEN, UNAME..., PLEN, PASSWD...]`，严格使用 UTF-8 字节长度。
pub fn build_rfc1929_auth_packet(username: &str, password: &str) -> Result<Vec<u8>, UpstreamError> {
    let u_bytes = username.as_bytes();
    let p_bytes = password.as_bytes();

    if u_bytes.is_empty() || u_bytes.len() > 255 {
        return Err(UpstreamError::AuthRejected(format!(
            "用户名 UTF-8 字节长度必须在 1..=255 之间 (当前 {})",
            u_bytes.len()
        )));
    }
    if p_bytes.is_empty() || p_bytes.len() > 255 {
        return Err(UpstreamError::AuthRejected(format!(
            "密码 UTF-8 字节长度必须在 1..=255 之间 (当前 {})",
            p_bytes.len()
        )));
    }

    let mut packet = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
    packet.push(RFC1929_VERSION);
    packet.push(u_bytes.len() as u8);
    packet.extend_from_slice(u_bytes);
    packet.push(p_bytes.len() as u8);
    packet.extend_from_slice(p_bytes);
    Ok(packet)
}

/// 构造 SOCKS5 `CONNECT` 请求报文（域名原样写入 `0x03` 帧，零本地解析）
pub fn build_socks5_connect_request(target: &TargetAddr) -> Result<Vec<u8>, UpstreamError> {
    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[SOCKS5_VERSION, CMD_CONNECT, 0x00]);

    match target {
        TargetAddr::Ipv4(ip, port) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(UpstreamError::InvalidTarget(
                    "域名 UTF-8 长度超出 1..=255 范围".to_string(),
                ));
            }
            req.push(ATYP_DOMAIN);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
            req.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ipv6(ip, port) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }

    Ok(req)
}

/// 连接上游 SOCKS5 代理并完成方法协商、（可选）RFC 1929 认证及 `CONNECT` 目标隧道建立。
pub async fn connect_via_upstream(
    upstream: &ResolvedUpstreamProxy,
    target: &TargetAddr,
    timeout: Duration,
) -> Result<TcpStream, UpstreamError> {
    tokio::time::timeout(timeout, connect_via_upstream_inner(upstream, target))
        .await
        .map_err(|_| UpstreamError::ConnectTimeout)?
}

/// 使用默认 10 秒超时的便捷封装
pub async fn connect_via_upstream_default(
    upstream: &ResolvedUpstreamProxy,
    target: &TargetAddr,
) -> Result<TcpStream, UpstreamError> {
    connect_via_upstream(
        upstream,
        target,
        Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
    )
    .await
}

async fn connect_via_upstream_inner(
    upstream: &ResolvedUpstreamProxy,
    target: &TargetAddr,
) -> Result<TcpStream, UpstreamError> {
    let connect_spec = if upstream.host.contains(':') && !upstream.host.starts_with('[') {
        format!("[{}]:{}", upstream.host, upstream.port)
    } else {
        format!("{}:{}", upstream.host, upstream.port)
    };

    let mut stream = TcpStream::connect(&connect_spec)
        .await
        .map_err(|e| UpstreamError::ProxyUnreachable(e.to_string()))?;
    let _ = stream.set_nodelay(true);

    // 1. 方法协商：开启认证时同时提议 0x00 与 0x02；未开启认证时仅提议 0x00
    let greeting: &[u8] = if upstream.auth.is_some() {
        &[SOCKS5_VERSION, 0x02, AUTH_METHOD_NONE, AUTH_METHOD_USERPASS]
    } else {
        &[SOCKS5_VERSION, 0x01, AUTH_METHOD_NONE]
    };

    stream
        .write_all(greeting)
        .await
        .map_err(|e| UpstreamError::ProxyUnreachable(format!("发送握手报文失败: {}", e)))?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await.map_err(|e| {
        UpstreamError::ProtocolViolation(format!("读取上游方法协商响应失败: {}", e))
    })?;

    if method_resp[0] != SOCKS5_VERSION {
        return Err(UpstreamError::ProtocolViolation(format!(
            "非 SOCKS5 响应版本: 0x{:02X}",
            method_resp[0]
        )));
    }

    match method_resp[1] {
        AUTH_METHOD_NONE => {
            // 上游无需认证，直接进入 CONNECT
        }
        AUTH_METHOD_USERPASS => {
            let Some((ref username, ref password)) = upstream.auth else {
                return Err(UpstreamError::AuthRejected(
                    "上游代理要求用户名/密码认证，但当前配置未启用认证".to_string(),
                ));
            };

            let mut auth_pkt = build_rfc1929_auth_packet(username, password)?;
            let write_res = stream.write_all(&auth_pkt).await;
            // 发送后立即清零报文缓冲中的密码字节
            auth_pkt.fill(0);
            write_res.map_err(|e| {
                UpstreamError::ProxyUnreachable(format!("发送 RFC 1929 认证请求失败: {}", e))
            })?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await.map_err(|e| {
                UpstreamError::AuthRejected(format!("读取上游认证响应断开: {}", e))
            })?;

            if auth_resp[0] != RFC1929_VERSION {
                return Err(UpstreamError::ProtocolViolation(format!(
                    "RFC 1929 子协商版本异常: 0x{:02X}",
                    auth_resp[0]
                )));
            }
            if auth_resp[1] != 0x00 {
                return Err(UpstreamError::AuthRejected(format!(
                    "认证被拒绝 (状态码 0x{:02X})",
                    auth_resp[1]
                )));
            }
        }
        AUTH_METHOD_NO_ACCEPTABLE => {
            return Err(UpstreamError::AuthRejected(
                "上游代理不支持当前认证方式 (0xFF)".to_string(),
            ));
        }
        other => {
            return Err(UpstreamError::ProtocolViolation(format!(
                "上游返回未知认证方法: 0x{:02X}",
                other
            )));
        }
    }

    // 2. 发送 CONNECT 目标请求（域名保持 0x03 原样透传）
    let connect_req = build_socks5_connect_request(target)?;
    stream
        .write_all(&connect_req)
        .await
        .map_err(|e| UpstreamError::ProxyUnreachable(format!("发送 CONNECT 请求失败: {}", e)))?;

    // 3. 读取 CONNECT 响应头 [VER, REP, RSV, ATYP]
    let mut resp_head = [0u8; 4];
    stream.read_exact(&mut resp_head).await.map_err(|e| {
        UpstreamError::ProtocolViolation(format!("读取 CONNECT 响应头失败: {}", e))
    })?;

    if resp_head[0] != SOCKS5_VERSION {
        return Err(UpstreamError::ProtocolViolation(format!(
            "CONNECT 响应版本异常: 0x{:02X}",
            resp_head[0]
        )));
    }

    let rep = resp_head[1];
    let atyp = resp_head[3];

    // 完整消费 BND.ADDR + BND.PORT，保证底层 TCP 流对齐到纯应用数据载荷起点
    match atyp {
        ATYP_IPV4 => {
            let mut tail = [0u8; 6];
            let _ = stream.read_exact(&mut tail).await;
        }
        ATYP_IPV6 => {
            let mut tail = [0u8; 18];
            let _ = stream.read_exact(&mut tail).await;
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            if stream.read_exact(&mut len_buf).await.is_ok() {
                let mut tail = vec![0u8; (len_buf[0] as usize) + 2];
                let _ = stream.read_exact(&mut tail).await;
            }
        }
        other => {
            if rep == REP_SUCCEEDED {
                return Err(UpstreamError::ProtocolViolation(format!(
                    "CONNECT 响应携带未知 ATYP: 0x{:02X}",
                    other
                )));
            }
        }
    }

    if rep != REP_SUCCEEDED {
        return Err(UpstreamError::TargetRejected {
            rep,
            description: describe_socks5_rep(rep).to_string(),
        });
    }

    Ok(stream)
}
