//! 本地回环代理转发器（Forwarder）
//!
//! 核心职责与安全红线（需求文档 4.1）：
//! 1. 严格绑定 `127.0.0.1:0`（仅限本机回环，严禁 `0.0.0.0`），获取系统随机端口；
//! 2. 同端口首字节协议嗅探：`0x05` 走无认证 SOCKS5 `CONNECT`（`BIND`/`UDP` 返回 `0x07`），
//!    其余走 HTTP `CONNECT`（非 `CONNECT` 返回 `405`），所有域名一律以 `ATYP=0x03` 原样透传上游；
//! 3. 最大并发连接数 512，上游握手超时 10 秒，单连接空闲超时 5 分钟；
//! 4. 引用计数生命周期管理，归零自动关闭监听并释放端口；
//! 5. 暴露 `trip()` 紧急熔断接口：通过 `CancellationToken` 立即关闭监听并毫秒级中断所有活跃双向流；
//! 6. 维护连续上游握手失败计数，达到阈值时向 `Watchdog` 发送即时唤醒信号。

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::constants::{
    FORWARDER_FAIL_STREAK_THRESHOLD, FORWARDER_MAX_CONNECTIONS, FORWARDER_PREFERRED_PORT,
    TUNNEL_IDLE_TIMEOUT_SECS, UPSTREAM_CONNECT_TIMEOUT_SECS,
};
use crate::human_errors::HumanizedError;
use crate::logger::{LogKind, Logger};
use crate::proxy_store::ResolvedUpstreamProxy;
use crate::socks5::{
    connect_via_upstream, TargetAddr, UpstreamError, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    AUTH_METHOD_NONE, AUTH_METHOD_NO_ACCEPTABLE, CMD_CONNECT, REP_ADDR_TYPE_NOT_SUPPORTED,
    REP_COMMAND_NOT_SUPPORTED, REP_SUCCEEDED, SOCKS5_VERSION,
};

/// 转发器引用持有者类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseOwner {
    SafeBrowser,
    ClaudeCodeCli,
    ClaudeDesktop,
    CheckOrWatchdog,
    BackgroundDaemon,
}

impl LeaseOwner {
    pub fn label(self) -> &'static str {
        match self {
            LeaseOwner::SafeBrowser => "安全浏览器",
            LeaseOwner::ClaudeCodeCli => "Claude Code (CLI)",
            LeaseOwner::ClaudeDesktop => "Claude 桌面端",
            LeaseOwner::CheckOrWatchdog => "检测/巡检任务",
            LeaseOwner::BackgroundDaemon => "系统托盘后台转发",
        }
    }
}

/// 推送给前端状态栏的转发器状态快照（对齐需求文档 6.3 & 8.3 `forwarder-state`）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ForwarderStateSnapshot {
    Stopped,
    #[serde(rename_all = "camelCase")]
    Running {
        port: u16,
        active_connections: usize,
        lease_count: usize,
    },
    #[serde(rename_all = "camelCase")]
    Tripped {
        reason: String,
    },
}

/// 转发器运行时可调参数（支持单元测试注入较短超时快速验证）
#[derive(Debug, Clone)]
pub struct ForwarderOptions {
    pub max_connections: usize,
    pub upstream_connect_timeout: Duration,
    pub tunnel_idle_timeout: Duration,
    pub fail_streak_threshold: u32,
}

impl Default for ForwarderOptions {
    fn default() -> Self {
        Self {
            max_connections: FORWARDER_MAX_CONNECTIONS,
            upstream_connect_timeout: Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            tunnel_idle_timeout: Duration::from_secs(TUNNEL_IDLE_TIMEOUT_SECS),
            fail_streak_threshold: FORWARDER_FAIL_STREAK_THRESHOLD,
        }
    }
}

/// 跟踪最近一次读写活动时间戳的异步流包装器（用于精确判定单连接空闲超时）
struct ActivityTrackedStream {
    inner: TcpStream,
    epoch: Instant,
    last_active_ms: Arc<AtomicU64>,
}

impl ActivityTrackedStream {
    fn new(inner: TcpStream, epoch: Instant, last_active_ms: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            epoch,
            last_active_ms,
        }
    }

    #[inline]
    fn touch(&self) {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.last_active_ms.store(elapsed, Ordering::Relaxed);
    }
}

impl AsyncRead for ActivityTrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        poll
    }
}

impl AsyncWrite for ActivityTrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                self.touch();
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 单个本地回环转发器运行实例内核
pub struct RunningForwarderCore {
    pub proxy_id: String,
    upstream_signature: String,
    pub listen_addr: SocketAddr,
    cancel_token: CancellationToken,
    done_notify: Arc<Notify>,
    active_connections: Arc<AtomicUsize>,
    consecutive_upstream_failures: Arc<AtomicU32>,
    last_upstream_error: Arc<Mutex<Option<UpstreamError>>>,
}

impl RunningForwarderCore {
    /// 启动一个严格绑定在 `127.0.0.1:0` 的转发器实例
    pub async fn spawn(
        upstream: ResolvedUpstreamProxy,
        options: ForwarderOptions,
        logger: Arc<Logger>,
        failure_alert_notify: Option<Arc<Notify>>,
        state_change_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Arc<Self>, HumanizedError> {
        Self::spawn_with_preferred_port(
            upstream,
            0,
            options,
            logger,
            failure_alert_notify,
            state_change_hook,
        )
        .await
    }

    /// 启动严格绑定在 `127.0.0.1` 的转发器实例（优先绑定 `preferred_port`，被占用时自动平滑回退随机端口）
    pub async fn spawn_with_preferred_port(
        upstream: ResolvedUpstreamProxy,
        preferred_port: u16,
        options: ForwarderOptions,
        logger: Arc<Logger>,
        failure_alert_notify: Option<Arc<Notify>>,
        state_change_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Arc<Self>, HumanizedError> {
        let listener = if preferred_port != 0 {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, preferred_port)).await {
                Ok(l) => l,
                Err(_) => TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .map_err(|e| {
                        HumanizedError::forwarder_bind_failed(&e.to_string(), Some(&logger))
                    })?,
            }
        } else {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| HumanizedError::forwarder_bind_failed(&e.to_string(), Some(&logger)))?
        };

        let listen_addr = listener
            .local_addr()
            .map_err(|e| HumanizedError::forwarder_bind_failed(&e.to_string(), Some(&logger)))?;

        // 安全双重校验：确保绑定的绝对是 127.0.0.1 回环地址
        if !listen_addr.ip().is_loopback() {
            return Err(HumanizedError::forwarder_bind_failed(
                "回环地址校验未通过",
                Some(&logger),
            ));
        }

        let upstream_signature = format!(
            "{}:{}:{}:{}",
            upstream.id,
            upstream.host,
            upstream.port,
            upstream.auth.is_some()
        );
        let cancel_token = CancellationToken::new();
        let done_notify = Arc::new(Notify::new());
        let active_connections = Arc::new(AtomicUsize::new(0));
        let consecutive_upstream_failures = Arc::new(AtomicU32::new(0));
        let last_upstream_error = Arc::new(Mutex::new(None));
        let semaphore = Arc::new(Semaphore::new(options.max_connections));

        let core = Arc::new(Self {
            proxy_id: upstream.id.clone(),
            upstream_signature,
            listen_addr,
            cancel_token: cancel_token.clone(),
            done_notify: done_notify.clone(),
            active_connections: active_connections.clone(),
            consecutive_upstream_failures: consecutive_upstream_failures.clone(),
            last_upstream_error: last_upstream_error.clone(),
        });

        let upstream_arc = Arc::new(upstream);
        let logger_loop = logger.clone();
        let options_loop = options.clone();

        tokio::spawn(async move {
            loop {
                let accept_res = tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    res = listener.accept() => res,
                };

                let (client_stream, _peer_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(e) => {
                        logger_loop.warn(LogKind::App, format!("Forwarder accept 异常: {}", e));
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        logger_loop.warn(
                            LogKind::App,
                            format!(
                                "Forwarder 并发连接已达上限 ({}), 拒绝新建本地连接",
                                options_loop.max_connections
                            ),
                        );
                        drop(client_stream);
                        continue;
                    }
                };

                let conn_cancel = cancel_token.child_token();
                let upstream_cfg = upstream_arc.clone();
                let active_counter = active_connections.clone();
                let fail_streak = consecutive_upstream_failures.clone();
                let last_err_slot = last_upstream_error.clone();
                let fail_notify = failure_alert_notify.clone();
                let hook = state_change_hook.clone();
                let conn_opts = options_loop.clone();
                let conn_logger = logger_loop.clone();

                active_counter.fetch_add(1, Ordering::SeqCst);
                if let Some(ref h) = hook {
                    h();
                }

                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_downstream_connection(
                        client_stream,
                        upstream_cfg,
                        conn_opts,
                        conn_cancel,
                        fail_streak,
                        last_err_slot,
                        fail_notify,
                        conn_logger,
                    )
                    .await;

                    active_counter.fetch_sub(1, Ordering::SeqCst);
                    if let Some(ref h) = hook {
                        h();
                    }
                });
            }

            // listener 在此作用域结束自动 Drop，释放本地监听端口
            drop(listener);
            done_notify.notify_waiters();
        });

        Ok(core)
    }

    pub fn port(&self) -> u16 {
        self.listen_addr.port()
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn consecutive_upstream_failures(&self) -> u32 {
        self.consecutive_upstream_failures.load(Ordering::SeqCst)
    }

    pub fn take_last_upstream_error(&self) -> Option<UpstreamError> {
        self.last_upstream_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    pub fn peek_last_upstream_error(&self) -> Option<UpstreamError> {
        self.last_upstream_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// 立即停止监听并中断所有活跃转发连接
    pub fn shutdown_now(&self) {
        self.cancel_token.cancel();
    }

    /// 等待监听 Socket 完全关闭释放
    pub async fn wait_closed(&self) {
        if self.cancel_token.is_cancelled() {
            // 给异步循环极短调度机会释放 TcpListener
            tokio::task::yield_now().await;
        } else {
            self.done_notify.notified().await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_downstream_connection(
    mut client: TcpStream,
    upstream: Arc<ResolvedUpstreamProxy>,
    options: ForwarderOptions,
    cancel_token: CancellationToken,
    fail_streak: Arc<AtomicU32>,
    last_err_slot: Arc<Mutex<Option<UpstreamError>>>,
    fail_notify: Option<Arc<Notify>>,
    logger: Arc<Logger>,
) -> io::Result<()> {
    let _ = client.set_nodelay(true);

    // 1. 首字节协议嗅探（10s 客户端握手超时，同时响应熔断取消）
    let mut first = [0u8; 1];
    let first_read = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return Ok(()),
        res = tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut first)) => res,
    };

    match first_read {
        Ok(Ok(_)) => {}
        _ => return Ok(()),
    }

    // 2. 分流处理 SOCKS5 (0x05) 与 HTTP CONNECT
    let (mut upstream_stream, leftover_client_bytes) = if first[0] == SOCKS5_VERSION {
        match negotiate_downstream_socks5(
            &mut client,
            &upstream,
            &options,
            &cancel_token,
            &fail_streak,
            &last_err_slot,
            fail_notify.as_ref(),
            &logger,
        )
        .await?
        {
            Some(up) => (up, Vec::new()),
            None => return Ok(()),
        }
    } else {
        match negotiate_downstream_http_connect(
            &mut client,
            first[0],
            &upstream,
            &options,
            &cancel_token,
            &fail_streak,
            &last_err_slot,
            fail_notify.as_ref(),
            &logger,
        )
        .await?
        {
            Some(pair) => pair,
            None => return Ok(()),
        }
    };

    if !leftover_client_bytes.is_empty() {
        upstream_stream.write_all(&leftover_client_bytes).await?;
    }

    // 3. 双向零阻塞数据转发（受 CancellationToken 熔断信号与 5 分钟空闲超时双重保护）
    let epoch = Instant::now();
    let last_active_ms = Arc::new(AtomicU64::new(0));
    let mut tracked_client = ActivityTrackedStream::new(client, epoch, last_active_ms.clone());
    let mut tracked_upstream =
        ActivityTrackedStream::new(upstream_stream, epoch, last_active_ms.clone());

    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            // 熔断或转发器关闭：立即退出作用域 Drop 两侧 Socket，实现毫秒级断流
        }
        _ = monitor_idle_timeout(epoch, last_active_ms, options.tunnel_idle_timeout) => {
            logger.info(LogKind::App, "Forwarder 单连接空闲超时已自动回收");
        }
        _ = tokio::io::copy_bidirectional(&mut tracked_client, &mut tracked_upstream) => {}
    }

    Ok(())
}

async fn monitor_idle_timeout(
    epoch: Instant,
    last_active_ms: Arc<AtomicU64>,
    idle_timeout: Duration,
) {
    let timeout_ms = idle_timeout.as_millis() as u64;
    let check_step = (idle_timeout / 4)
        .max(Duration::from_millis(50))
        .min(Duration::from_secs(5));

    loop {
        tokio::time::sleep(check_step).await;
        let now_ms = epoch.elapsed().as_millis() as u64;
        let last_ms = last_active_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) >= timeout_ms {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn negotiate_downstream_socks5(
    client: &mut TcpStream,
    upstream: &ResolvedUpstreamProxy,
    options: &ForwarderOptions,
    cancel_token: &CancellationToken,
    fail_streak: &AtomicU32,
    last_err_slot: &Mutex<Option<UpstreamError>>,
    fail_notify: Option<&Arc<Notify>>,
    logger: &Logger,
) -> io::Result<Option<TcpStream>> {
    // 1. 读取客户端认证方法列表（本地仅接受无认证 0x00）
    let mut nmethods_buf = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut nmethods_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client greeting timeout"))??;

    let nmethods = nmethods_buf[0] as usize;
    if nmethods == 0 {
        let _ = client
            .write_all(&[SOCKS5_VERSION, AUTH_METHOD_NO_ACCEPTABLE])
            .await;
        return Ok(None);
    }

    let mut methods = vec![0u8; nmethods];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut methods))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client methods timeout"))??;

    if !methods.contains(&AUTH_METHOD_NONE) {
        let _ = client
            .write_all(&[SOCKS5_VERSION, AUTH_METHOD_NO_ACCEPTABLE])
            .await;
        return Ok(None);
    }

    client
        .write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE])
        .await?;

    // 2. 读取客户端请求头 [VER, CMD, RSV, ATYP]
    let mut req_head = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut req_head))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client request timeout"))??;

    if req_head[0] != SOCKS5_VERSION {
        return Ok(None);
    }

    let cmd = req_head[1];
    let atyp = req_head[3];

    // 先把客户端发来的地址字段完整读出
    let target = match read_socks5_target_addr(client, atyp).await? {
        Some(t) => t,
        None => {
            send_socks5_reply(client, REP_ADDR_TYPE_NOT_SUPPORTED).await?;
            return Ok(None);
        }
    };

    // BIND (0x02) 与 UDP ASSOCIATE (0x03) 等非 CONNECT 命令一律明确返回 0x07
    if cmd != CMD_CONNECT {
        send_socks5_reply(client, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(None);
    }

    // 3. 连接上游代理（支持熔断取消抢占）
    let upstream_res = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return Ok(None),
        res = connect_via_upstream(upstream, &target, options.upstream_connect_timeout) => res,
    };

    match upstream_res {
        Ok(up_stream) => {
            fail_streak.store(0, Ordering::SeqCst);
            send_socks5_reply(client, REP_SUCCEEDED).await?;
            Ok(Some(up_stream))
        }
        Err(up_err) => {
            record_upstream_failure(
                &up_err,
                options.fail_streak_threshold,
                fail_streak,
                last_err_slot,
                fail_notify,
                logger,
            );
            send_socks5_reply(client, up_err.to_socks5_rep()).await?;
            Ok(None)
        }
    }
}

async fn read_socks5_target_addr(
    client: &mut TcpStream,
    atyp: u8,
) -> io::Result<Option<TargetAddr>> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            client.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Some(TargetAddr::Ipv4(ip, port)))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            if len == 0 {
                return Ok(None);
            }
            let mut buf = vec![0u8; len + 2];
            client.read_exact(&mut buf).await?;
            let Ok(domain) = String::from_utf8(buf[..len].to_vec()) else {
                return Ok(None);
            };
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            // 域名铁律：直接构造 TargetAddr::Domain，绝不调用任何本地 DNS 解析
            Ok(Some(TargetAddr::Domain(domain, port)))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            client.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Some(TargetAddr::Ipv6(ip, port)))
        }
        _ => Ok(None),
    }
}

async fn send_socks5_reply(client: &mut TcpStream, rep: u8) -> io::Result<()> {
    let pkt = [
        SOCKS5_VERSION,
        rep,
        0x00,
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    client.write_all(&pkt).await?;
    client.flush().await
}

#[allow(clippy::too_many_arguments)]
async fn negotiate_downstream_http_connect(
    client: &mut TcpStream,
    first_byte: u8,
    upstream: &ResolvedUpstreamProxy,
    options: &ForwarderOptions,
    cancel_token: &CancellationToken,
    fail_streak: &AtomicU32,
    last_err_slot: &Mutex<Option<UpstreamError>>,
    fail_notify: Option<&Arc<Notify>>,
    logger: &Logger,
) -> io::Result<Option<(TcpStream, Vec<u8>)>> {
    const MAX_HEADER_BYTES: usize = 8192;
    let mut header_buf = Vec::with_capacity(512);
    header_buf.push(first_byte);

    let header_end_pos = loop {
        if let Some(pos) = find_double_crlf(&header_buf) {
            break pos;
        }
        if header_buf.len() >= MAX_HEADER_BYTES {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(None);
        }

        let mut chunk = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http connect header timeout"))??;
        if n == 0 {
            return Ok(None);
        }
        header_buf.extend_from_slice(&chunk[..n]);
    };

    let leftover = header_buf[header_end_pos + 4..].to_vec();
    let header_str = String::from_utf8_lossy(&header_buf[..header_end_pos]);
    let first_line = header_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");

    // 非 CONNECT 请求（如普通 GET http://...）明确返回 405 Method Not Allowed（需求 4.1）
    if !method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        client.flush().await?;
        return Ok(None);
    }

    let Some(target) = parse_http_connect_authority(authority) else {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        client.flush().await?;
        return Ok(None);
    };

    let upstream_res = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => return Ok(None),
        res = connect_via_upstream(upstream, &target, options.upstream_connect_timeout) => res,
    };

    match upstream_res {
        Ok(up_stream) => {
            fail_streak.store(0, Ordering::SeqCst);
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
            Ok(Some((up_stream, leftover)))
        }
        Err(up_err) => {
            record_upstream_failure(
                &up_err,
                options.fail_streak_threshold,
                fail_streak,
                last_err_slot,
                fail_notify,
                logger,
            );
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await?;
            client.flush().await?;
            Ok(None)
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_http_connect_authority(authority: &str) -> Option<TargetAddr> {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(after_open) = trimmed.strip_prefix('[') {
        let close = after_open.find(']')?;
        let ipv6_host = &after_open[..close];
        let rest = &after_open[close + 1..];
        let port = if let Some(p_str) = rest.strip_prefix(':') {
            p_str.parse::<u16>().ok()?
        } else {
            443
        };
        TargetAddr::from_host_port(ipv6_host, port).ok()
    } else if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        let port = port_str.parse::<u16>().ok()?;
        TargetAddr::from_host_port(host, port).ok()
    } else {
        TargetAddr::from_host_port(trimmed, 443).ok()
    }
}

fn record_upstream_failure(
    err: &UpstreamError,
    threshold: u32,
    fail_streak: &AtomicU32,
    last_err_slot: &Mutex<Option<UpstreamError>>,
    fail_notify: Option<&Arc<Notify>>,
    logger: &Logger,
) {
    if let Ok(mut guard) = last_err_slot.lock() {
        *guard = Some(err.clone());
    }

    if err.is_upstream_fault() {
        let count = fail_streak.fetch_add(1, Ordering::SeqCst) + 1;
        logger.warn(
            LogKind::App,
            format!(
                "Forwarder 上游握手异常 (连续第 {} 次): {}",
                count, err
            ),
        );
        if count >= threshold {
            if let Some(notify) = fail_notify {
                notify.notify_one();
            }
        }
    }
}

// ============================================================================
// 引用计数管理器与紧急熔断控制器（ForwarderManager）
// ============================================================================

struct ManagedState {
    active_core: Option<Arc<RunningForwarderCore>>,
    leases: HashMap<u64, LeaseOwner>,
    next_lease_id: u64,
    tripped_reason: Option<String>,
}

/// 持有本地转发器引用计数的 RAII 租约守卫（Drop 时自动释放引用，归零时自动关停释放端口）
pub struct ForwarderLease {
    manager: Arc<ForwarderManager>,
    core: Arc<RunningForwarderCore>,
    lease_id: u64,
    released: bool,
}

impl ForwarderLease {
    pub fn port(&self) -> u16 {
        self.core.port()
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.core.listen_addr
    }

    pub fn core(&self) -> &Arc<RunningForwarderCore> {
        &self.core
    }

    /// 显式提前释放租约
    pub fn release(mut self) {
        if !self.released {
            self.released = true;
            self.manager.release_lease_internal(self.lease_id);
        }
    }
}

impl Drop for ForwarderLease {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.manager.release_lease_internal(self.lease_id);
        }
    }
}

/// 独立短生命周期转发器（供表单「测试连接」验证未保存代理或熔断态下隔离重检使用）
pub struct EphemeralForwarder {
    core: Arc<RunningForwarderCore>,
}

impl EphemeralForwarder {
    pub fn port(&self) -> u16 {
        self.core.port()
    }

    pub fn core(&self) -> &Arc<RunningForwarderCore> {
        &self.core
    }

    pub async fn shutdown(self) {
        self.core.shutdown_now();
        self.core.wait_closed().await;
    }
}

impl Drop for EphemeralForwarder {
    fn drop(&mut self) {
        self.core.shutdown_now();
    }
}

/// 全局本地转发器管理器
pub struct ForwarderManager {
    logger: Arc<Logger>,
    options: ForwarderOptions,
    state: Mutex<ManagedState>,
    /// 当上游连续失败达到阈值时唤醒 Watchdog
    upstream_suspect_notify: Arc<Notify>,
    /// 状态变更事件回调（供 Tauri 向前端广播 `forwarder-state`）
    state_listener: Mutex<Option<Arc<dyn Fn(ForwarderStateSnapshot) + Send + Sync>>>,
}

impl ForwarderManager {
    pub fn new(logger: Arc<Logger>) -> Arc<Self> {
        Self::with_options(logger, ForwarderOptions::default())
    }

    pub fn with_options(logger: Arc<Logger>, options: ForwarderOptions) -> Arc<Self> {
        Arc::new(Self {
            logger,
            options,
            state: Mutex::new(ManagedState {
                active_core: None,
                leases: HashMap::new(),
                next_lease_id: 1,
                tripped_reason: None,
            }),
            upstream_suspect_notify: Arc::new(Notify::new()),
            state_listener: Mutex::new(None),
        })
    }

    /// 注册前端状态推送回调
    pub fn set_state_listener<F>(&self, callback: F)
    where
        F: Fn(ForwarderStateSnapshot) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.state_listener.lock() {
            *guard = Some(Arc::new(callback));
        }
    }

    /// 暴露给 Watchdog 订阅的「疑似上游掉线」唤醒通知器
    pub fn upstream_suspect_notifier(&self) -> Arc<Notify> {
        self.upstream_suspect_notify.clone()
    }

    /// 获取当前转发器实时快照
    pub fn snapshot(&self) -> ForwarderStateSnapshot {
        let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref reason) = guard.tripped_reason {
            return ForwarderStateSnapshot::Tripped {
                reason: reason.clone(),
            };
        }
        if let Some(ref core) = guard.active_core {
            return ForwarderStateSnapshot::Running {
                port: core.port(),
                active_connections: core.active_connections(),
                lease_count: guard.leases.len(),
            };
        }
        ForwarderStateSnapshot::Stopped
    }

    fn emit_snapshot(&self) {
        let snap = self.snapshot();
        let cb_opt = self
            .state_listener
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(cb) = cb_opt {
            cb(snap);
        }
    }

    /// 申请共享转发器租约（浏览器 / CLI / 桌面端 / 常规检测共用）
    pub async fn acquire_lease(
        self: &Arc<Self>,
        upstream: ResolvedUpstreamProxy,
        owner: LeaseOwner,
    ) -> Result<ForwarderLease, HumanizedError> {
        // 1. 先检查是否处于熔断锁定态或可直接复用已有同配置实例
        let desired_sig = format!(
            "{}:{}:{}:{}",
            upstream.id,
            upstream.host,
            upstream.port,
            upstream.auth.is_some()
        );

        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref reason) = guard.tripped_reason {
                return Err(HumanizedError::new(
                    "FORWARDER_TRIPPED",
                    "安全熔断已触发，转发器已紧急锁定 → 请先点击「重新检测」通过后再启动",
                    reason,
                    Some(&self.logger),
                ));
            }

            if let Some(existing) = guard.active_core.clone() {
                if existing.upstream_signature == desired_sig {
                    let lease_id = guard.next_lease_id;
                    guard.next_lease_id += 1;
                    guard.leases.insert(lease_id, owner);
                    drop(guard);
                    self.emit_snapshot();
                    return Ok(ForwarderLease {
                        manager: self.clone(),
                        core: existing,
                        lease_id,
                        released: false,
                    });
                } else if !guard.leases.is_empty() {
                    return Err(HumanizedError::new(
                        "PROXY_BUSY",
                        "当前已有其他代理会话正在使用转发器，请先关闭安全浏览器或相关终端后再切换",
                        format!("Active proxy_id={} busy", existing.proxy_id),
                        Some(&self.logger),
                    ));
                }
            }
        }

        // 2. 启动新的本地回环转发器实例
        let weak_self = Arc::downgrade(self);
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(mgr) = weak_self.upgrade() {
                mgr.emit_snapshot();
            }
        });

        let new_core = RunningForwarderCore::spawn_with_preferred_port(
            upstream,
            FORWARDER_PREFERRED_PORT,
            self.options.clone(),
            self.logger.clone(),
            Some(self.upstream_suspect_notify.clone()),
            Some(hook),
        )
        .await?;

        self.logger.info(
            LogKind::App,
            format!(
                "本地转发器已启动: 127.0.0.1:{} (持有者: {})",
                new_core.port(),
                owner.label()
            ),
        );

        let lease_id = {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            // 二次检查：防止异步启动期间恰好触发了熔断
            if let Some(ref reason) = guard.tripped_reason {
                new_core.shutdown_now();
                return Err(HumanizedError::new(
                    "FORWARDER_TRIPPED",
                    "安全熔断已触发，转发器已锁定",
                    reason,
                    Some(&self.logger),
                ));
            }
            let id = guard.next_lease_id;
            guard.next_lease_id += 1;
            guard.active_core = Some(new_core.clone());
            guard.leases.insert(id, owner);
            id
        };

        self.emit_snapshot();

        Ok(ForwarderLease {
            manager: self.clone(),
            core: new_core,
            lease_id,
            released: false,
        })
    }

    /// 启动互不干扰的临时单测转发器（供编辑表单测试或熔断态重新检测使用）
    pub async fn spawn_ephemeral(
        &self,
        upstream: ResolvedUpstreamProxy,
    ) -> Result<EphemeralForwarder, HumanizedError> {
        let core = RunningForwarderCore::spawn(
            upstream,
            self.options.clone(),
            self.logger.clone(),
            None,
            None,
        )
        .await?;
        Ok(EphemeralForwarder { core })
    }

    fn release_lease_internal(&self, lease_id: u64) {
        let mut shutdown_core: Option<Arc<RunningForwarderCore>> = None;
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(owner) = guard.leases.remove(&lease_id) {
                if guard.leases.is_empty() {
                    if let Some(core) = guard.active_core.take() {
                        let port = core.port();
                        shutdown_core = Some(core);
                        self.logger.info(
                            LogKind::App,
                            format!(
                                "转发器最后持有者 ({}) 已退出，释放本地端口 127.0.0.1:{}",
                                owner.label(),
                                port
                            ),
                        );
                    }
                }
            }
        }

        if let Some(core) = shutdown_core {
            core.shutdown_now();
        }
        self.emit_snapshot();
    }

    /// 紧急熔断（Fail-Safe `trip()`）：
    /// 立即关闭监听 Socket 并通过 `CancellationToken` 中断所有活跃连接的 `copy_bidirectional`！
    pub fn trip(&self, reason: impl Into<String>) {
        let reason_str = reason.into();
        let core_to_kill = {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.leases.clear();
            guard.tripped_reason = Some(reason_str.clone());
            guard.active_core.take()
        };

        if let Some(core) = core_to_kill {
            let port = core.port();
            core.shutdown_now();
            self.logger.error(
                LogKind::App,
                format!(
                    "【安全熔断】已紧急切断本地转发器 127.0.0.1:{} 所有活跃连接，原因: {}",
                    port, reason_str
                ),
            );
        } else {
            self.logger.error(
                LogKind::App,
                format!("【安全熔断】转发器已进入锁定状态，原因: {}", reason_str),
            );
        }

        self.emit_snapshot();
    }

    /// 当用户手动「重新检测」且关键项全部通过后，解除转发器熔断锁定态
    pub fn clear_trip_lock(&self) {
        let mut changed = false;
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.tripped_reason.is_some() {
                guard.tripped_reason = None;
                changed = true;
            }
        }
        if changed {
            self.logger
                .info(LogKind::App, "重新检测关键项全绿通过，转发器已解除熔断锁定");
            self.emit_snapshot();
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tripped_reason
            .is_some()
    }

    /// 应用退出时强制清理所有监听与活跃连接
    pub fn shutdown_all(&self) {
        let core_opt = {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.leases.clear();
            guard.active_core.take()
        };
        if let Some(core) = core_opt {
            core.shutdown_now();
        }
        self.emit_snapshot();
    }
}
