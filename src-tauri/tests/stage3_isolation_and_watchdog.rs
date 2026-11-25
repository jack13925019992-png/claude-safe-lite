//! 阶段 3 自动化测试套件（跨平台兼容 Windows Job Object 与 macOS/Unix Process Group）：
//! 进程树精准强杀、浏览器防泄露参数、Watchdog 自动熔断与防误报复测、重检解锁闭环、安全环境重置

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[cfg(windows)]
use claude_safe_lite_lib::browser_launcher::Win32ProcessJob;
#[cfg(unix)]
use claude_safe_lite_lib::browser_launcher::UnixProcessGroup;
use claude_safe_lite_lib::browser_launcher::{
    build_hardened_browser_args, detect_browser, BrowserKind, BrowserLauncher,
};
use claude_safe_lite_lib::checker::{CheckEndpointsConfig, Checker};
use claude_safe_lite_lib::forwarder::{ForwarderManager, LeaseOwner};
use claude_safe_lite_lib::logger::{LogKind, Logger};
use claude_safe_lite_lib::proxy_store::{ProxyStore, ResolvedUpstreamProxy, SaveProxyInput};
use claude_safe_lite_lib::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, AUTH_METHOD_NONE, CMD_CONNECT, REP_SUCCEEDED, SOCKS5_VERSION,
};
use claude_safe_lite_lib::tool_launcher::{execute_reset_environment, ResetEnvOptions};
use claude_safe_lite_lib::watchdog::{TripKind, Watchdog, WatchdogAlertPayload};

fn temp_test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "csl_v2_阶段三测试 空格_{}_{}",
        tag,
        Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 生成跨平台长驻休眠模拟浏览器脚本（Windows `.cmd` / Unix 可执行 `.sh`）
fn create_mock_sleep_script(dir: &Path, base_name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let p = dir.join(format!("{}.cmd", base_name));
        fs::write(&p, "@ping.exe -n 30 127.0.0.1 >nul\r\n").unwrap();
        p
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(format!("{}.sh", base_name));
        fs::write(&p, "#!/bin/sh\nsleep 30\n").unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
        p
    }
}

/// 启动极简无认证本地 Mock SOCKS5 上游代理，将连接桥接到指定本地 HTTP 服务器
async fn spawn_simple_socks5_bridge(backend_port: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                if s.read_exact(&mut g).await.is_err() || g[0] != SOCKS5_VERSION {
                    return;
                }
                let mut m = vec![0u8; g[1] as usize];
                if s.read_exact(&mut m).await.is_err() {
                    return;
                }
                let _ = s.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await;

                let mut h = [0u8; 4];
                if s.read_exact(&mut h).await.is_err() || h[1] != CMD_CONNECT {
                    return;
                }
                match h[3] {
                    ATYP_DOMAIN => {
                        let mut l = [0u8; 1];
                        if s.read_exact(&mut l).await.is_err() {
                            return;
                        }
                        let mut d = vec![0u8; l[0] as usize + 2];
                        if s.read_exact(&mut d).await.is_err() {
                            return;
                        }
                    }
                    ATYP_IPV4 => {
                        let mut d = [0u8; 6];
                        if s.read_exact(&mut d).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }

                if s.write_all(&[
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

                if let Ok(mut backend) = TcpStream::connect(("127.0.0.1", backend_port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut backend).await;
                }
            });
        }
    });

    port
}

#[cfg(windows)]
#[test]
fn test_win32_job_object_kills_process_tree_without_touching_outside_process() {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let mut outside_proc = Command::new("ping.exe")
        .args(["-n", "30", "127.0.0.1"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动外部对照进程失败");

    let mut job = Win32ProcessJob::create().expect("创建 Win32 Job Object 失败");
    let mut tree_cmd = Command::new("cmd.exe");
    tree_cmd
        .args(["/c", "ping.exe -n 30 127.0.0.1 >nul"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut root_in_job = job
        .spawn_command_in_job(&mut tree_cmd, CREATE_NO_WINDOW)
        .expect("在 Job 内零竞态挂起启动子进程失败");

    std::thread::sleep(Duration::from_millis(350));
    let active_in_job = job.active_process_count();
    assert!(
        active_in_job >= 1,
        "Job Object 内应检测到正在运行的进程树, 实际={}",
        active_in_job
    );

    job.terminate_all(1);
    std::thread::sleep(Duration::from_millis(120));

    assert_eq!(job.active_process_count(), 0);
    assert!(
        root_in_job.try_wait().unwrap().is_some(),
        "Job 内根进程必须已立即终止"
    );
    assert!(
        outside_proc.try_wait().unwrap().is_none(),
        "外部非安全浏览器进程严禁被误杀！"
    );

    let _ = outside_proc.kill();
    let _ = outside_proc.wait();
}

#[cfg(unix)]
#[test]
fn test_unix_process_group_kills_process_tree_without_touching_outside_process() {
    let mut outside_proc = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动外部对照进程失败");

    let mut pgrp = UnixProcessGroup::create().expect("创建进程组沙箱失败");
    let mut tree_cmd = Command::new("/bin/sh");
    tree_cmd
        .args(["-c", "/bin/sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let _pid = pgrp
        .spawn_command_in_group(&mut tree_cmd)
        .expect("在独立进程组内启动子进程失败");

    std::thread::sleep(Duration::from_millis(250));
    assert!(pgrp.has_active_processes(), "独立进程组内应检测到活跃进程树");

    pgrp.terminate_all();
    std::thread::sleep(Duration::from_millis(120));

    assert!(!pgrp.has_active_processes(), "独立进程组内进程必须已彻底终止");
    assert!(
        outside_proc.try_wait().unwrap().is_none(),
        "外部非安全浏览器进程严禁被误杀！"
    );

    let _ = outside_proc.kill();
    let _ = outside_proc.wait();
}

#[test]
fn test_browser_detection_priority_and_hardened_cli_args() {
    let dir = temp_test_dir("browser_args");
    let fake_browser = dir.join("my_custom_brave_bin");
    fs::write(&fake_browser, b"MZ-mock-binary").unwrap();

    // 1. 手动指定有效路径时最高优先级命中 Custom
    let detected =
        detect_browser(Some(&fake_browser.to_string_lossy()), None).expect("应命中手动指定路径");
    assert_eq!(detected.kind, BrowserKind::Custom);
    assert_eq!(detected.path, fake_browser);

    // 2. 手动指定不存在的路径时明确报错拦截（不静默忽略）
    let bad_path = dir.join("does_not_exist_bin");
    assert!(detect_browser(Some(&bad_path.to_string_lossy()), None).is_err());

    // 3. 校验全部防泄露启动参数（含中文与空格隔离目录）
    let profile_dir = dir.join("profiles").join("节点_测试 空格ID");
    let args: Vec<String> = build_hardened_browser_args(&profile_dir, 54321)
        .into_iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect();

    assert!(args
        .iter()
        .any(|a| a.starts_with("--user-data-dir=") && a.contains("节点_测试 空格ID")));
    assert!(args.contains(&"--proxy-server=socks5://127.0.0.1:54321".to_string()));
    assert!(args.contains(&"--no-first-run".to_string()));
    assert!(args.contains(&"--no-default-browser-check".to_string()));
    assert!(args.contains(&"--disable-quic".to_string()));
    assert!(args.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string()));
    assert!(args.contains(&"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string()));
    assert!(args.contains(&"--test-type".to_string()));
    assert!(args.contains(&"https://claude.ai".to_string()));

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_watchdog_leak_zero_delay_trip_anti_false_positive_and_recheck_unlock() {
    let dir = temp_test_dir("watchdog_fsm");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let forwarder_mgr = ForwarderManager::new(logger.clone());
    let browser_launcher = BrowserLauncher::new(logger.clone());

    let mock_mode = Arc::new(AtomicUsize::new(0));
    let mock_mode_srv = mock_mode.clone();

    let http_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = http_listener.accept().await {
            let mode_ref = mock_mode_srv.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let cur = mode_ref.load(Ordering::SeqCst);

                if cur == 1 {
                    mode_ref.store(0, Ordering::SeqCst);
                    let _ = stream
                        .write_all(b"HTTP/1.1 500 Internal Error\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                if cur == 2 {
                    let _ = stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }

                let ip_str = if cur == 3 {
                    "114.114.114.114"
                } else {
                    "203.0.113.50"
                };

                let body = if req.contains("/dns") {
                    r#"{"dns":{"ip":"172.64.36.2","geo":"United States","country_code":"US"}}"#
                        .to_string()
                } else if req.contains("/risk") {
                    r#"{"is_datacenter":false,"is_proxy":false,"is_vpn":false}"#.to_string()
                } else if req.contains("/claude") {
                    "OK".to_string()
                } else {
                    format!(
                        r#"{{"success":true,"ip":"{}","country_code":"US","country":"United States"}}"#,
                        ip_str
                    )
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    let socks_port = spawn_simple_socks5_bridge(http_port).await;
    let endpoints = CheckEndpointsConfig {
        item_timeout: Duration::from_secs(2),
        probe_host: "probe.claude.invalid".to_string(),
        probe_port: 443,
        geo_ip_urls: vec!["http://geo.claude.invalid/geo".to_string()],
        fast_ip_urls: vec!["http://geo.claude.invalid/geo".to_string()],
        ip_risk_primary_template: "http://risk.claude.invalid/risk?q={ip}".to_string(),
        ip_risk_fallback_template: "http://risk.claude.invalid/risk?q={ip}".to_string(),
        claude_url: "http://web.claude.invalid/claude".to_string(),
        dns_leak_url_override: Some("http://{rand}.edns.claude.invalid/dns".to_string()),
    };

    let checker = Checker::with_endpoints(forwarder_mgr.clone(), logger.clone(), endpoints);
    let watchdog = Watchdog::with_retry_delay(
        forwarder_mgr.clone(),
        browser_launcher.clone(),
        checker.clone(),
        logger.clone(),
        Duration::from_millis(80),
    );

    let alerts: Arc<Mutex<Vec<WatchdogAlertPayload>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let alerts_c = alerts.clone();
        watchdog.set_alert_listener(move |payload| {
            alerts_c.lock().unwrap().push(payload);
        });
    }

    let upstream = ResolvedUpstreamProxy {
        id: "wd-proxy".to_string(),
        name: "美西守护节点".to_string(),
        host: "127.0.0.1".to_string(),
        port: socks_port,
        auth: None,
    };

    // 场景 A：验证单次瞬时抖动（mode=1）经复测恢复后不误报、不熔断
    let lease = forwarder_mgr
        .acquire_lease(upstream.clone(), LeaseOwner::SafeBrowser)
        .await
        .unwrap();
    mock_mode.store(1, Ordering::SeqCst);
    watchdog.start_monitoring(
        lease.port(),
        "203.0.113.50".to_string(),
        Some("US".to_string()),
        Duration::from_millis(120),
    );
    tokio::time::sleep(Duration::from_millis(320)).await;
    assert!(
        !watchdog.is_locked() && !forwarder_mgr.is_tripped(),
        "单次瞬时网络抖动复测恢复后严禁误触发熔断！"
    );

    // 场景 B：模拟出口 IP 突变为直连泄露（mode=3） -> 0 延迟立即熔断并杀死伪装浏览器进程！
    let fake_browser_script = create_mock_sleep_script(&dir, "mock_browser");
    let _launched = browser_launcher
        .launch_isolated(
            upstream.id.clone(),
            upstream.name.clone(),
            dir.join("profiles").join(&upstream.id),
            Some(&fake_browser_script.to_string_lossy()),
            lease,
        )
        .unwrap();
    assert!(browser_launcher.is_running());

    mock_mode.store(3, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(260)).await;

    assert!(watchdog.is_locked(), "检测到出口 IP 偏离基线必须立即锁定");
    assert!(forwarder_mgr.is_tripped(), "转发器必须已紧急断流");
    assert!(
        !browser_launcher.is_running(),
        "安全浏览器隔离进程树必须已被强制终止"
    );

    {
        let recorded = alerts.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].trip_kind, TripKind::IpOrDnsLeak);
        assert_eq!(
            recorded[0].notification_body,
            "检测到 IP/DNS 泄露，已强制关闭安全浏览器"
        );
    }

    // 场景 C：代理未恢复（mode=2 掉线）时重新检测 -> 关键项未全绿，严禁解除熔断锁定！
    mock_mode.store(2, Ordering::SeqCst);
    let bad_rep = checker.run_all_checks(upstream.clone(), |_| {}).await.unwrap();
    assert!(!watchdog.try_unlock_after_recheck(&bad_rep));
    assert!(watchdog.is_locked());

    // 场景 D：代理恢复正常（mode=0）后重新检测 -> 关键项全绿且无泄露，自动解除锁定！
    mock_mode.store(0, Ordering::SeqCst);
    let good_rep = checker.run_all_checks(upstream.clone(), |_| {}).await.unwrap();
    assert!(good_rep.can_unlock_circuit_breaker());
    assert!(watchdog.try_unlock_after_recheck(&good_rep));
    assert!(!watchdog.is_locked());
    assert!(!forwarder_mgr.is_tripped());

    // 场景 E：验证持续掉线（mode=2）经二次复测确认后触发 ProxyDisconnected 熔断文案
    let lease2 = forwarder_mgr
        .acquire_lease(upstream, LeaseOwner::SafeBrowser)
        .await
        .unwrap();
    mock_mode.store(2, Ordering::SeqCst);
    watchdog.start_monitoring(
        lease2.port(),
        "203.0.113.50".to_string(),
        Some("US".to_string()),
        Duration::from_millis(100),
    );
    tokio::time::sleep(Duration::from_millis(380)).await;
    assert!(watchdog.is_locked());
    {
        let recorded = alerts.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[1].trip_kind, TripKind::ProxyDisconnected);
        assert_eq!(
            recorded[1].notification_body,
            "代理连接已断开，为防止泄露已强制关闭安全浏览器"
        );
    }

    let app_logs = logger.read_tail(LogKind::App, Some(50)).unwrap().join("\n");
    let launch_logs = logger
        .read_tail(LogKind::Launch, Some(50))
        .unwrap()
        .join("\n");
    assert!(app_logs.contains("安全熔断触发"));
    assert!(launch_logs.contains("安全熔断触发"));

    drop(lease2);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_reset_environment_safety_interception_and_selective_clean() {
    let dir = temp_test_dir("reset_env");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let store = ProxyStore::load_or_init(dir.clone(), logger.clone()).unwrap();
    let forwarder_mgr = ForwarderManager::new(logger.clone());
    let browser_launcher = BrowserLauncher::new(logger.clone());

    let saved = store
        .save_proxy(SaveProxyInput {
            id: None,
            name: "保留的节点".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth_enabled: false,
            username: String::new(),
            password: None,
        })
        .unwrap();

    let profile_dir = store.profile_dir_for(&saved.id);
    fs::create_dir_all(&profile_dir).unwrap();
    fs::write(profile_dir.join("Cookies"), b"dummy-cookie").unwrap();

    let fake_browser_script = create_mock_sleep_script(&dir, "sleep_browser");

    let upstream = store.resolve_active_upstream().unwrap().unwrap();
    let lease = forwarder_mgr
        .acquire_lease(upstream, LeaseOwner::SafeBrowser)
        .await
        .unwrap();

    browser_launcher
        .launch_isolated(
            saved.id.clone(),
            saved.name.clone(),
            profile_dir.clone(),
            Some(&fake_browser_script.to_string_lossy()),
            lease,
        )
        .unwrap();

    // 1. 浏览器正在运行时，重置环境必须被硬性拦截拒绝
    let opts = ResetEnvOptions {
        clean_browser_profiles: true,
        clean_logs: true,
        clear_proxies: false,
        restore_default_settings: false,
    };
    assert!(execute_reset_environment(&opts, &browser_launcher, &store, &logger).is_err());

    // 2. 关闭安全浏览器后执行重置：隔离目录被清空，但代理配置完好保留！
    browser_launcher.force_kill("测试关闭");
    assert!(!browser_launcher.is_running());

    let res = execute_reset_environment(&opts, &browser_launcher, &store, &logger).unwrap();
    assert!(res.message.contains("全部浏览器隔离目录"));
    assert!(!profile_dir.join("Cookies").exists());
    assert_eq!(store.list_proxies().0.len(), 1, "未勾选清除代理时必须保留代理配置");

    let _ = fs::remove_dir_all(&dir);
}
