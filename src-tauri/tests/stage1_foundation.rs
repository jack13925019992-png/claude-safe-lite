//! 阶段 1 自动化测试套件：DPAPI 加解密、强制脱敏轮转日志、多代理配置原子持久化与快捷解析

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use uuid::Uuid;

use claude_safe_lite_lib::constants::{CONFIG_BACKUP_FILE_NAME, CONFIG_FILE_NAME};
use claude_safe_lite_lib::crypto::{dpapi_decrypt, dpapi_encrypt, CryptoError};
use claude_safe_lite_lib::logger::{mask_username, LogKind, Logger};
use claude_safe_lite_lib::proxy_store::{
    parse_proxy_text, AppSettings, ProxyStore, SaveProxyInput,
};

fn create_isolated_dir(tag: &str) -> PathBuf {
    // 特意包含中文与空格，验证 Windows 非 ASCII 路径安全性（需求文档 0.6）
    let dir = std::env::temp_dir().join(format!(
        "csl_v2_阶段一测试 空格目录_{}_{}",
        tag,
        Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("创建临时测试目录失败");
    dir
}

#[test]
fn test_dpapi_roundtrip_and_fail_closed_security() {
    let samples = [
        "simplePass123",
        "P@ss:w0rd/with#special%chars@127.0.0.1:1080",
        "含中文与特殊符号密钥_!@#$%^&*()_+-=[]{}|;':\",./<>?",
    ];

    for sample in samples {
        let encrypted = dpapi_encrypt(sample).expect("DPAPI 加密应当成功");
        assert_ne!(encrypted, sample, "密文严禁与明文相同");
        assert!(!encrypted.contains(sample), "密文严禁包含明文子串");

        let decrypted = dpapi_decrypt(&encrypted).expect("DPAPI 解密应当成功");
        assert_eq!(decrypted, sample);
    }

    // Fail-Closed 验证：空明文、空密文、非法 Base64、伪造 Base64 明文一律拒绝，绝不回退
    assert!(matches!(dpapi_encrypt(""), Err(CryptoError::EmptyPlaintext)));
    assert!(matches!(dpapi_decrypt(""), Err(CryptoError::EmptyCiphertext)));
    assert!(matches!(
        dpapi_decrypt("not-valid-base64!!!"),
        Err(CryptoError::InvalidBase64)
    ));
    let forged_b64 = BASE64_STD.encode(b"plaintext_pretending_to_be_dpapi_blob");
    assert!(matches!(
        dpapi_decrypt(&forged_b64),
        Err(CryptoError::DpapiUnprotectFailed(_))
    ));
}

#[test]
fn test_logger_masking_and_zero_plaintext_redaction() {
    // 1. 验证代理用户名脱敏规则：不足 2 位显示 ***，>= 2 位显示前 2 位 + ***
    assert_eq!(mask_username(""), "***");
    assert_eq!(mask_username(" "), "***");
    assert_eq!(mask_username("x"), "***");
    assert_eq!(mask_username("中"), "***");
    assert_eq!(mask_username("ab"), "ab***");
    assert_eq!(mask_username("user01"), "us***");
    assert_eq!(mask_username("张三丰"), "张三***");

    // 2. 验证已注册凭据与内联 URL 凭据双重脱敏
    let dir = create_isolated_dir("logger_sanitize");
    let logger = Logger::new(&dir).unwrap();

    let special_pwd = "P@ss:w0rd/123#45%67";
    logger.replace_credentials(vec![(
        "proxy_admin".to_string(),
        Some(special_pwd.to_string()),
    )]);

    logger.error(
        LogKind::Check,
        format!(
            "握手异常 user=proxy_admin pwd={} raw_url=socks5://inline_user:Inl!ne@Pwd:99#1@1.2.3.4:1080",
            special_pwd
        ),
    );

    let lines = logger.read_tail(LogKind::Check, Some(20)).unwrap();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];

    assert!(!line.contains(special_pwd), "严禁泄漏已注册密码: {}", line);
    assert!(!line.contains("Inl!ne@Pwd:99#1"), "严禁泄漏内联密码: {}", line);
    assert!(!line.contains("proxy_admin"), "严禁泄漏完整用户名: {}", line);
    assert!(!line.contains("inline_user"), "严禁泄漏内联完整用户名: {}", line);
    assert!(line.contains("pr***"));
    assert!(line.contains("in***"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_logger_rotation_retains_max_3_files() {
    let dir = create_isolated_dir("logger_rotate");
    let logger = Logger::with_max_bytes(&dir, 512).unwrap();

    for i in 0..45 {
        logger.info(
            LogKind::App,
            format!("第 {:02} 条用于验证单文件超限滚动轮转的测试日志数据记录", i),
        );
    }

    let base = logger.log_file_path(LogKind::App);
    let rot1 = Logger::rotated_path(&base, 1);
    let rot2 = Logger::rotated_path(&base, 2);
    let rot3 = Logger::rotated_path(&base, 3);
    let rot4 = Logger::rotated_path(&base, 4);

    assert!(base.exists());
    assert!(rot1.exists());
    assert!(rot2.exists());
    assert!(rot3.exists());
    assert!(!rot4.exists(), "最多只保留 .1 .2 .3 三份历史日志");

    assert!(fs::metadata(&base).unwrap().len() <= 512);
    assert!(fs::metadata(&rot1).unwrap().len() <= 512);

    let export_path = dir.join("exported.txt");
    logger.export_to(LogKind::App, &export_path).unwrap();
    assert!(fs::metadata(&export_path).unwrap().len() > 0);

    logger.clear(LogKind::App).unwrap();
    assert!(!base.exists() && !rot1.exists() && !rot3.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_proxy_quick_paste_parsing_edge_cases() {
    // 格式 1：host:port:user:pass（密码含多个冒号及 @ / # %）
    let d1 = parse_proxy_text("us-res.node.example:10800:acc_01:p@ss:w0rd:part3/slash#hash%25")
        .expect("应按前 3 个冒号切分");
    assert_eq!(d1.host, "us-res.node.example");
    assert_eq!(d1.port, 10800);
    assert!(d1.auth_enabled);
    assert_eq!(d1.username, "acc_01");
    assert_eq!(d1.password, "p@ss:w0rd:part3/slash#hash%25");

    // 格式 2：socks5://user:pass@host:port（从最后一个 @ 切分）
    let d2 = parse_proxy_text("socks5://user99:my@p@ss:word/1#2%3@203.0.113.88:9050")
        .expect("应从最后一个 @ 切分认证区与主机区");
    assert_eq!(d2.host, "203.0.113.88");
    assert_eq!(d2.port, 9050);
    assert!(d2.auth_enabled);
    assert_eq!(d2.username, "user99");
    assert_eq!(d2.password, "my@p@ss:word/1#2%3");

    // 格式 3：IPv6 支持
    let d3 = parse_proxy_text("socks5://v6u:v6@p:1@[2001:db8::1]:1080").unwrap();
    assert_eq!(d3.host, "2001:db8::1");
    assert_eq!(d3.port, 1080);
    assert_eq!(d3.password, "v6@p:1");

    let d4 = parse_proxy_text("[2001:db8::2]:2080:u2:p:2:3").unwrap();
    assert_eq!(d4.host, "2001:db8::2");
    assert_eq!(d4.port, 2080);
    assert_eq!(d4.password, "p:2:3");

    // 无认证格式与非法输入拦截
    let d5 = parse_proxy_text("127.0.0.1:1080").unwrap();
    assert!(!d5.auth_enabled);
    assert!(parse_proxy_text("http://1.2.3.4:8080").is_err());
    assert!(parse_proxy_text("999.1.1.1:1080").is_err());
    assert!(parse_proxy_text("1.2.3.4:0").is_err());
}

#[test]
fn test_proxy_store_crud_atomic_bak_recovery_and_zero_plaintext() {
    let dir = create_isolated_dir("proxy_store");
    let logger = Arc::new(Logger::new(&dir).unwrap());
    let store = ProxyStore::load_or_init(dir.clone(), logger.clone()).unwrap();

    let secret = "S3cr3t@Pwd:With#Special%Chars!";
    let created = store
        .save_proxy(SaveProxyInput {
            id: None,
            name: "美西静态住宅 01".to_string(),
            host: "198.51.100.10".to_string(),
            port: 1080,
            auth_enabled: true,
            username: "res_user".to_string(),
            password: Some(secret.to_string()),
        })
        .unwrap();

    assert!(created.has_password);
    // 前端序列化绝不含明文与密文
    let frontend_json = serde_json::to_string(&created).unwrap();
    assert!(!frontend_json.contains(secret));
    assert!(!frontend_json.contains("passwordEncrypted"));

    // 落盘 config.json 绝不含明文密码
    let on_disk = fs::read_to_string(dir.join(CONFIG_FILE_NAME)).unwrap();
    assert!(!on_disk.contains(secret));
    assert!(on_disk.contains("passwordEncrypted"));

    // 编辑时密码框留空 -> 保持原加密密码不变（触发 .bak 备份）
    let updated = store
        .save_proxy(SaveProxyInput {
            id: Some(created.id.clone()),
            name: "美西静态住宅 01-Pro".to_string(),
            host: "198.51.100.10".to_string(),
            port: 1081,
            auth_enabled: true,
            username: "res_user".to_string(),
            password: None,
        })
        .unwrap();
    assert!(updated.has_password);
    assert!(dir.join(CONFIG_BACKUP_FILE_NAME).exists());

    let upstream = store.resolve_active_upstream().unwrap().unwrap();
    assert_eq!(upstream.port, 1081);
    assert_eq!(
        upstream.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
        Some(("res_user", secret))
    );

    // 复制配置并测试删除激活项自动切换
    let copied = store.duplicate_proxy(&created.id).unwrap();
    assert!(copied.name.contains("副本"));
    assert!(copied.has_password);

    let next_active = store.delete_proxy(&created.id).unwrap();
    assert_eq!(next_active.as_deref(), Some(copied.id.as_str()));

    // 更新设置后再人为破坏主 config.json -> 验证启动自动从 .bak 回退修复
    store
        .update_settings(AppSettings {
            custom_browser_path: None,
            safe_mode_enabled: true,
            watchdog_interval_sec: 60,
        })
        .unwrap();
    fs::write(dir.join(CONFIG_FILE_NAME), "<<< CORRUPTED FILE >>>").unwrap();

    let reloaded = ProxyStore::load_or_init(dir.clone(), logger).unwrap();
    assert!(reloaded.take_recovered_notice());
    let (proxies, active) = reloaded.list_proxies();
    assert_eq!(proxies.len(), 1);
    assert_eq!(active.as_deref(), Some(copied.id.as_str()));

    let _ = fs::remove_dir_all(&dir);
}
