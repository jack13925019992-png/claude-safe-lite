//! 阶段 2 自动化测试套件：
//! 本地 Mock SOCKS5 上游 + 本地 Forwarder + 五项检测引擎 Checker 全链路验证

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use claude_safe_lite_lib::checker::{CheckEndpointsConfig, Checker, LightStatus};
use claude_safe_lite_lib::forwarder::{ForwarderManager, ForwarderOptions, LeaseOwner};
use claude_safe_lite_lib::logger::Logger;
use claude_safe_lite_lib::proxy_store::ResolvedUpstreamProxy;
use claude_safe_lite_lib::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, AUTH_METHOD_NONE, AUTH_METHOD_USERPASS, CMD_BIND, CMD_CONNECT,
    CMD_UDP_ASSOCIATE, REP_COMMAND_NOT_SUPPORTED, REP_HOST_UNREACHABLE, REP_SUCCEEDED,
    RFC1929_VERSION, SOCKS5_VERSION,
};

fn temp_test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("csl_v2_stage2_{}_{}", tag, Uuid::new_v4()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Mock SOCKS5 上游代理配置与观测记录
struct MockUpstreamServer {
    addr: SocketAddr,
    observed_domains: Arc<Mutex<Vec<(String, u16)>>>,
    accepted_count: Arc<AtomicUsize>,
}

#[derive(Clone)]
enum MockUpstreamBehavior {
    /// 正常带认证或无认证代理，将所有流量转发到指定 `backend_addr`（或直接回显测试载荷）
    ForwardTo {
        expected_auth: Option<(String, String)>,
        backend_addr: Option<SocketAddr>,
    },
    /// 故意挂起不回复，模拟连接/握手超时
    BlackholeHang,
}

async fn spawn_mock_socks5_upstream(behavior: MockUpstreamBehavior) -> MockUpstreamServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed_domains: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let accepted_count = Arc::new(AtomicUsize::new(0));

    let domains_clone = observed_domains.clone();
    let count_clone = accepted_count.clone();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            count_clone.fetch_add(1, Ordering::SeqCst);
            let beh = behavior.clone();
            let doms = domains_clone.clone();

            tokio::spawn(async move {
                match beh {
                    MockUpstreamBehavior::BlackholeHang => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        let _ = sock.shutdown().await;
                    }
                    MockUpstreamBehavior::ForwardTo {
                        expected_auth,
                        backend_addr,
                    } => {
                        let mut head = [0u8; 2];
                        if sock.read_exact(&mut head).await.is_err() || head[0] != SOCKS5_VERSION {
                            return;
                        }
                        let mut methods = vec![0u8; head[1] as usize];
                        if sock.read_exact(&mut methods).await.is_err() {
                            return;
                        }

                        if let Some((exp_user, exp_pass)) = expected_auth {
                            if !methods.contains(&AUTH_METHOD_USERPASS) {
                                let _ = sock.write_all(&[SOCKS5_VERSION, 0xFF]).await;
                                return;
                            }
                            if sock
                                .write_all(&[SOCKS5_VERSION, AUTH_METHOD_USERPASS])
                                .await
                                .is_err()
                            {
                                return;
                            }

                            // 解析 RFC 1929 报文（严格校验 UTF-8 字节长度）
                            let mut ver_ulen = [0u8; 2];
                            if sock.read_exact(&mut ver_ulen).await.is_err()
                                || ver_ulen[0] != RFC1929_VERSION
                            {
                                return;
                            }
                            let mut u_bytes = vec![0u8; ver_ulen[1] as usize];
                            if sock.read_exact(&mut u_bytes).await.is_err() {
                                return;
                            }
                            let mut plen = [0u8; 1];
                            if sock.read_exact(&mut plen).await.is_err() {
                                return;
                            }
                            let mut p_bytes = vec![0u8; plen[0] as usize];
                            if sock.read_exact(&mut p_bytes).await.is_err() {
                                return;
                            }

                            if u_bytes == exp_user.as_bytes() && p_bytes == exp_pass.as_bytes() {
                                let _ = sock.write_all(&[RFC1929_VERSION, 0x00]).await;
                            } else {
                                let _ = sock.write_all(&[RFC1929_VERSION, 0x01]).await;
                                return;
                            }
                        } else {
                            let _ = sock
                                .write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE])
                                .await;
                        }

                        // 读取 CONNECT 请求
                        let mut req = [0u8; 4];
                        if sock.read_exact(&mut req).await.is_err() || req[1] != CMD_CONNECT {
                            return;
                        }
                        match req[3] {
                            ATYP_DOMAIN => {
                                let mut dlen = [0u8; 1];
                                if sock.read_exact(&mut dlen).await.is_err() {
                                    return;
                                }
                                let len = dlen[0] as usize;
                                let mut dbuf = vec![0u8; len + 2];
                                if sock.read_exact(&mut dbuf).await.is_err() {
                                    return;
                                }
                                let domain = String::from_utf8_lossy(&dbuf[..len]).to_string();
                                let port = u16::from_be_bytes([dbuf[len], dbuf[len + 1]]);
                                doms.lock().unwrap().push((domain, port));
                            }
                            ATYP_IPV4 => {
                                let mut buf = [0u8; 6];
                                if sock.read_exact(&mut buf).await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        }

                        // 回复 CONNECT 成功
                        if sock
                            .write_all(&[
                                SOCKS5_VERSION,
                                REP_SUCCEEDED,
                                0x00,
                                ATYP_IPV4,
                                127,
                                0,
                                0,
                                1,
                                0,
                                0,
                            ])
                            .await
                            .is_err()
                        {
                            return;
                        }

                        if let Some(target_backend) = backend_addr {
                            if let Ok(mut backend) = TcpStream::connect(target_backend).await {
                                let _ = tokio::io::copy_bidirectional(&mut sock, &mut backend).await;
                            }
                        } else {
                            // Echo 模式：将收到的数据原样回显，用于测试双向流与 trip() 瞬时切断
                            let mut buf = [0u8; 1024];
                            while let Ok(n) = sock.read(&mut buf).await {
                                if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }
    });

    MockUpstreamServer {
        addr,
        observed_domains,
        accepted_count,
    }
}

#[tokio::test]
async fn test_rfc1929_special_and_multibyte_password_and_domain_passthrough() {
    let dir = temp_test_dir("rfc1929_domain");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let mgr = ForwarderManager::new(logger);

    // 密码同时包含 @ : / # % 以及多字节中文字符（验证 UTF-8 字节长度 != 字符数！）
    let user = "账号_admin";
    let pass = "密@码:P@ss/123#45%99!";
    assert_ne!(
        pass.chars().count(),
        pass.as_bytes().len(),
        "测试样本应包含多字节字符以验证 RFC1929 长度计算"
    );

    let mock_up = spawn_mock_socks5_upstream(MockUpstreamBehavior::ForwardTo {
        expected_auth: Some((user.to_string(), pass.to_string())),
        backend_addr: None,
    })
    .await;

    let lease = mgr
        .acquire_lease(
            ResolvedUpstreamProxy {
                id: "node-1".to_string(),
                name: "测试节点".to_string(),
                host: "127.0.0.1".to_string(),
                port: mock_up.addr.port(),
                auth: Some((user.to_string(), pass.to_string())),
            },
            LeaseOwner::SafeBrowser,
        )
        .await
        .unwrap();

    // 下游客户端以无认证 SOCKS5 连接本地 Forwarder，请求一个现实中不存在的虚拟域名
    let mut client = TcpStream::connect(("127.0.0.1", lease.port())).await.unwrap();
    client
        .write_all(&[SOCKS5_VERSION, 0x01, AUTH_METHOD_NONE])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, AUTH_METHOD_NONE]);

    let fake_domain = b"never-resolvable-locally.claude.invalid";
    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, fake_domain.len() as u8];
    req.extend_from_slice(fake_domain);
    req.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut c_resp = [0u8; 10];
    client.read_exact(&mut c_resp).await.unwrap();
    assert_eq!(c_resp[1], REP_SUCCEEDED, "应当握手与认证成功");

    // 验证双向数据收发正常
    client.write_all(b"ping-claude-v2").await.unwrap();
    let mut echo = [0u8; 14];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping-claude-v2");

    // 铁证：验证上游代理原封不动收到了 0x03 域名帧（零本地 DNS 解析）
    let observed = mock_up.observed_domains.lock().unwrap().clone();
    assert_eq!(
        observed,
        vec![("never-resolvable-locally.claude.invalid".to_string(), 443)]
    );

    drop(lease);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_http_connect_sniffing_405_and_socks5_unsupported_cmds() {
    let dir = temp_test_dir("sniffing");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let mgr = ForwarderManager::new(logger);

    let mock_up = spawn_mock_socks5_upstream(MockUpstreamBehavior::ForwardTo {
        expected_auth: Some(("cli_u".to_string(), "cli_p@1".to_string())),
        backend_addr: None,
    })
    .await;

    let lease = mgr
        .acquire_lease(
            ResolvedUpstreamProxy {
                id: "node-cli".to_string(),
                name: "CLI 节点".to_string(),
                host: "127.0.0.1".to_string(),
                port: mock_up.addr.port(),
                auth: Some(("cli_u".to_string(), "cli_p@1".to_string())),
            },
            LeaseOwner::ClaudeCodeCli,
        )
        .await
        .unwrap();

    // 1. 同端口发送 HTTP CONNECT 请求（附带预发载荷） -> 200 Connection Established 且域名原样透传上游
    let mut http_conn = TcpStream::connect(("127.0.0.1", lease.port())).await.unwrap();
    http_conn
        .write_all(
            b"CONNECT api.anthropic.invalid:443 HTTP/1.1\r\nHost: api.anthropic.invalid:443\r\n\r\nhello-from-cli",
        )
        .await
        .unwrap();

    let mut resp_buf = [0u8; 256];
    let n = http_conn.read(&mut resp_buf).await.unwrap();
    let resp_text = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_text.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n"),
        "HTTP CONNECT 应成功建立隧道, 实际收到: {}",
        resp_text
    );

    // 若粘包载荷已同时回显或紧随其后到达，验证完整收到 "hello-from-cli"
    let mut echoed = resp_buf[39..n].to_vec();
    while echoed.len() < b"hello-from-cli".len() {
        let mut more = [0u8; 64];
        let m = http_conn.read(&mut more).await.unwrap();
        echoed.extend_from_slice(&more[..m]);
    }
    assert_eq!(&echoed, b"hello-from-cli");

    // 2. 非 CONNECT 的普通 HTTP 请求 -> 明确返回 405 Method Not Allowed
    let mut bad_http = TcpStream::connect(("127.0.0.1", lease.port())).await.unwrap();
    bad_http
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut bad_resp = Vec::new();
    bad_http.read_to_end(&mut bad_resp).await.unwrap();
    let bad_str = String::from_utf8_lossy(&bad_resp);
    assert!(
        bad_str.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "非 CONNECT 应返回 405, 实际: {}",
        bad_str
    );

    // 3. SOCKS5 BIND (0x02) 与 UDP ASSOCIATE (0x03) -> 明确返回 0x07
    for unsupported_cmd in [CMD_BIND, CMD_UDP_ASSOCIATE] {
        let mut s = TcpStream::connect(("127.0.0.1", lease.port())).await.unwrap();
        s.write_all(&[SOCKS5_VERSION, 0x01, AUTH_METHOD_NONE])
            .await
            .unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[
            SOCKS5_VERSION,
            unsupported_cmd,
            0x00,
            ATYP_IPV4,
            1,
            1,
            1,
            1,
            0x00,
            0x35,
        ])
        .await
        .unwrap();
        let mut r = [0u8; 10];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], REP_COMMAND_NOT_SUPPORTED);
    }

    drop(lease);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_timeout_streak_wakeup_and_trip_millisecond_cutoff() {
    let dir = temp_test_dir("trip_and_timeout");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let mgr = ForwarderManager::with_options(
        logger,
        ForwarderOptions {
            max_connections: 64,
            upstream_connect_timeout: Duration::from_millis(250),
            tunnel_idle_timeout: Duration::from_secs(60),
            fail_streak_threshold: 3,
        },
    );

    // A. 验证上游挂起超时返回规范错误码 + 连续 3 次失败立即触发 Watchdog 唤醒通知
    let hang_up = spawn_mock_socks5_upstream(MockUpstreamBehavior::BlackholeHang).await;
    let suspect_notify = mgr.upstream_suspect_notifier();
    let notified_fut = suspect_notify.notified();
    tokio::pin!(notified_fut);

    let hang_lease = mgr
        .acquire_lease(
            ResolvedUpstreamProxy {
                id: "hang-node".to_string(),
                name: "超时节点".to_string(),
                host: "127.0.0.1".to_string(),
                port: hang_up.addr.port(),
                auth: None,
            },
            LeaseOwner::SafeBrowser,
        )
        .await
        .unwrap();

    for _ in 0..3 {
        let mut c = TcpStream::connect(("127.0.0.1", hang_lease.port()))
            .await
            .unwrap();
        c.write_all(&[SOCKS5_VERSION, 0x01, AUTH_METHOD_NONE])
            .await
            .unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&[SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4, 8, 8, 8, 8, 1, 187])
            .await
            .unwrap();
        let mut r = [0u8; 10];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], REP_HOST_UNREACHABLE, "超时应返回规范 SOCKS5 错误码");
    }

    tokio::time::timeout(Duration::from_millis(200), notified_fut)
        .await
        .expect("连续 3 次上游超时应立即触发 Watchdog 唤醒信号");
    drop(hang_lease);
    tokio::time::sleep(Duration::from_millis(30)).await;

    // B. 验证引用计数复用 + trip() 毫秒级切断活跃双向流 + 端口回收
    let echo_up = spawn_mock_socks5_upstream(MockUpstreamBehavior::ForwardTo {
        expected_auth: None,
        backend_addr: None,
    })
    .await;

    let up_cfg = ResolvedUpstreamProxy {
        id: "ok-node".to_string(),
        name: "正常节点".to_string(),
        host: "127.0.0.1".to_string(),
        port: echo_up.addr.port(),
        auth: None,
    };

    let lease1 = mgr
        .acquire_lease(up_cfg.clone(), LeaseOwner::SafeBrowser)
        .await
        .unwrap();
    let lease2 = mgr
        .acquire_lease(up_cfg.clone(), LeaseOwner::ClaudeCodeCli)
        .await
        .unwrap();
    let shared_port = lease1.port();
    assert_eq!(shared_port, lease2.port(), "同配置多持有者应复用同一本地端口");

    // 建立一条活跃 HTTP CONNECT 长连接
    let mut active_tunnel = TcpStream::connect(("127.0.0.1", shared_port))
        .await
        .unwrap();
    active_tunnel
        .write_all(b"CONNECT keepalive.claude.invalid:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut hdr = [0u8; 39];
    active_tunnel.read_exact(&mut hdr).await.unwrap();

    // 释放 lease1，因为 lease2 仍在，连接必须继续存活
    drop(lease1);
    active_tunnel.write_all(b"alive").await.unwrap();
    let mut pong = [0u8; 5];
    active_tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"alive");

    // 触发紧急熔断 trip() -> 活跃连接必须在毫秒级内被强制切断！
    mgr.trip("检测到出口 IP 泄露");
    assert!(mgr.is_tripped());

    let mut eof_buf = [0u8; 16];
    let cutoff_res = tokio::time::timeout(
        Duration::from_millis(150),
        active_tunnel.read(&mut eof_buf),
    )
    .await
    .expect("trip() 必须在 150ms 内立即中断活跃隧道");
    match cutoff_res {
        Ok(0) | Err(_) => {} // EOF 或 ConnectionReset 均表示已立即断流
        Ok(n) => panic!("熔断后不应再收到任何上游数据, 收到 {} 字节", n),
    }

    // 熔断锁定期间禁止再次租用业务转发器
    assert!(mgr
        .acquire_lease(up_cfg.clone(), LeaseOwner::SafeBrowser)
        .await
        .is_err());

    // 解锁后测试引用计数归零自动释放端口
    mgr.clear_trip_lock();
    let lease3 = mgr
        .acquire_lease(up_cfg, LeaseOwner::SafeBrowser)
        .await
        .unwrap();
    let temp_port = lease3.port();
    drop(lease3);
    drop(lease2);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        TcpStream::connect(("127.0.0.1", temp_port)).await.is_err(),
        "引用计数归零后本地转发端口必须立即关闭释放"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_checker_five_lights_linkage_and_claude_403_detection() {
    let dir = temp_test_dir("checker_suite");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let mgr = ForwarderManager::new(logger.clone());

    // 启动本地 Mock HTTP 检测目标服务（由 Mock SOCKS5 上游代理转发至此）
    let claude_status = Arc::new(AtomicU16::new(200));
    let claude_status_srv = claude_status.clone();

    let http_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = http_listener.accept().await {
            let status_code = claude_status_srv.load(Ordering::SeqCst);
            tokio::spawn(async move {
                let mut req_buf = [0u8; 2048];
                let Ok(n) = stream.read(&mut req_buf).await else {
                    return;
                };
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");

                let (status_line, extra_hdr, body) = if first_line.contains("/geo") {
                    (
                        "HTTP/1.1 200 OK",
                        "Content-Type: application/json\r\n",
                        r#"{"success":true,"ip":"198.51.100.77","country_code":"US","country":"United States","connection":{"isp":"AT&T Residential"}}"#,
                    )
                } else if first_line.contains("/risk") {
                    (
                        "HTTP/1.1 200 OK",
                        "Content-Type: application/json\r\n",
                        r#"{"is_datacenter":false,"is_proxy":false,"is_vpn":false,"is_abuser":false}"#,
                    )
                } else if first_line.contains("/dns") {
                    (
                        "HTTP/1.1 200 OK",
                        "Content-Type: application/json\r\n",
                        r#"{"dns":{"ip":"172.64.36.1","geo":"United States - Cloudflare","country_code":"US"}}"#,
                    )
                } else if first_line.contains("/claude") {
                    if status_code == 403 {
                        (
                            "HTTP/1.1 403 Forbidden",
                            "cf-mitigated: challenge\r\nContent-Type: text/html\r\n",
                            "<html>Just a moment...</html>",
                        )
                    } else {
                        ("HTTP/1.1 200 OK", "Content-Type: text/html\r\n", "<html>Claude</html>")
                    }
                } else {
                    ("HTTP/1.1 404 Not Found", "", "")
                };

                let response = format!(
                    "{}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    extra_hdr,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let mock_up = spawn_mock_socks5_upstream(MockUpstreamBehavior::ForwardTo {
        expected_auth: Some(("res_u".to_string(), "p@ss:w0rd/#%!".to_string())),
        backend_addr: Some(http_addr),
    })
    .await;

    let endpoints = CheckEndpointsConfig {
        item_timeout: Duration::from_secs(5),
        probe_host: "mock-probe.claude.invalid".to_string(),
        probe_port: 443,
        geo_ip_urls: vec!["http://mock-geo.claude.invalid/geo".to_string()],
        fast_ip_urls: vec!["http://mock-geo.claude.invalid/geo".to_string()],
        ip_risk_primary_template: "http://mock-risk.claude.invalid/risk?q={ip}".to_string(),
        ip_risk_fallback_template: "http://mock-risk.claude.invalid/risk?q={ip}".to_string(),
        claude_url: "http://mock-web.claude.invalid/claude".to_string(),
        dns_leak_url_override: Some("http://{rand}.mock-edns.claude.invalid/dns".to_string()),
    };

    let checker = Checker::with_endpoints(mgr, logger, endpoints);

    // 1. 全绿场景测试（所有域名均为 .invalid，若未走 Forwarder 透传必挂！）
    let good_upstream = ResolvedUpstreamProxy {
        id: "good-proxy".to_string(),
        name: "美国住宅节点".to_string(),
        host: "127.0.0.1".to_string(),
        port: mock_up.addr.port(),
        auth: Some(("res_u".to_string(), "p@ss:w0rd/#%!".to_string())),
    };

    let report_ok = checker.run_all_checks(good_upstream.clone(), |_| {}).await.unwrap();
    assert!(report_ok.critical_all_green(), "五项检测关键项应全绿: {:?}", report_ok);
    assert!(report_ok.can_unlock_circuit_breaker());
    assert_eq!(report_ok.exit_ip.as_deref(), Some("198.51.100.77"));
    assert_eq!(report_ok.country_code.as_deref(), Some("US"));
    for item in &report_ok.items {
        assert_eq!(item.status, LightStatus::Green, "检测项 {} 应为绿灯", item.title);
    }

    // 2. Claude 返回 403 / CF 拦截 -> 04 为红灯阻断，输出标准人话提示
    claude_status.store(403, Ordering::SeqCst);
    let report_403 = checker.run_all_checks(good_upstream, |_| {}).await.unwrap();
    assert!(!report_403.critical_all_green());
    assert_eq!(report_403.items[3].status, LightStatus::Red);
    assert!(report_403.items[3]
        .error
        .as_ref()
        .unwrap()
        .user_message
        .contains("更换静态住宅 IP"));

    // 3. 01 认证失败联动 -> 01 红灯（提示核对账号密码），02~05 全部保持 Pending（待定/灰）
    let bad_auth_upstream = ResolvedUpstreamProxy {
        id: "bad-auth".to_string(),
        name: "错误密码节点".to_string(),
        host: "127.0.0.1".to_string(),
        port: mock_up.addr.port(),
        auth: Some(("res_u".to_string(), "wrong_password".to_string())),
    };

    let report_fail01 = checker
        .run_all_checks(bad_auth_upstream, |_| {})
        .await
        .unwrap();
    assert_eq!(report_fail01.items[0].status, LightStatus::Red);
    assert_eq!(report_fail01.items[0].summary, "认证失败");
    for item in report_fail01.items.iter().skip(1) {
        assert_eq!(
            item.status,
            LightStatus::Pending,
            "01 失败时后续四项必须置为待定"
        );
    }

    assert!(mock_up.accepted_count.load(Ordering::SeqCst) >= 8);
    let _ = fs::remove_dir_all(&dir);
}
