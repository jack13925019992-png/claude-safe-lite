//! 全局配置常量与外部检测接口定义
//!
//! 如需替换出口 IP、IP 风险评分或 DNS 泄露检测接口，仅需修改本文件中的常量定义。

/// 应用在 `%APPDATA%` 下的专属数据目录名
pub const APP_DATA_DIR_NAME: &str = "ClaudeSafeLite";

/// 云端一机一码授权核销接口地址（部署 Cloudflare Worker 后自动填入真实线上地址）
pub const LICENSE_CLOUD_VERIFY_URL: &str =
    "https://claude-safe-lite-auth.csl-jack-auth.workers.dev/api/v1/verify";

/// 主配置文件、备份文件与原子写入临时文件名
pub const CONFIG_FILE_NAME: &str = "config.json";
pub const CONFIG_BACKUP_FILE_NAME: &str = "config.json.bak";
pub const CONFIG_TEMP_FILE_NAME: &str = "config.json.tmp";

/// 当前配置文件 Schema 版本号
pub const CONFIG_SCHEMA_VERSION: u32 = 2;

/// 日志目录与单文件轮转配置
pub const LOGS_DIR_NAME: &str = "logs";
pub const PROFILES_DIR_NAME: &str = "profiles";
pub const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MB
pub const LOG_MAX_ROTATED_FILES: usize = 3; // 保留 .1, .2, .3
pub const LOG_DEFAULT_TAIL_LINES: usize = 500;

/// 本地转发器（Forwarder）参数
pub const FORWARDER_BIND_HOST: &str = "127.0.0.1";
pub const FORWARDER_PREFERRED_PORT: u16 = 12223;
pub const FORWARDER_MAX_CONNECTIONS: usize = 512;
pub const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;
pub const TUNNEL_IDLE_TIMEOUT_SECS: u64 = 300; // 5 分钟
pub const FORWARDER_FAIL_STREAK_THRESHOLD: u32 = 3;

/// 五项检测与启动预检超时配置
pub const SINGLE_CHECK_TIMEOUT_SECS: u64 = 10;
pub const PREFLIGHT_CHECK_TIMEOUT_SECS: u64 = 15;

/// 安全模式后台巡检（Watchdog）参数
pub const WATCHDOG_DEFAULT_INTERVAL_SECS: u64 = 45;
pub const WATCHDOG_ALLOWED_INTERVALS: [u64; 3] = [30, 45, 60];
pub const WATCHDOG_RETRY_DELAY_SECS: u64 = 3;

// ============================================================================
// 五项检测与后台巡检公共接口配置（免 API Key，按主备顺序自动容灾，便于日后替换）
// ============================================================================

/// [01 代理连接] 连通性握手测试目标主机与端口
pub const PROBE_TARGET_HOST: &str = "cp.cloudflare.com";
pub const PROBE_TARGET_PORT: u16 = 443;

/// [02 出口 IP 与国家] 主备查询接口（均返回 JSON 含 IP 与国家代码）
pub const GEO_IP_ENDPOINTS: &[&str] = &[
    "https://ipwho.is/",
    "https://api.ip.sb/geoip",
    "https://ipinfo.io/json",
];

/// Watchdog 轻量出口 IP 巡检端点（低延迟纯文本/JSON）
pub const FAST_IP_TRACE_ENDPOINTS: &[&str] = &[
    "https://1.1.1.1/cdn-cgi/trace",
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/json",
];

/// Claude 官方不支持或高风控拦截国家/地区 ISO-3166 二字码（命中时 02 项判定为红灯阻断）
pub const UNSUPPORTED_COUNTRY_CODES: &[&str] = &[
    "CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU",
];

/// [03 IP 风险评分] 免 Key 风险属性查询接口模板（`{ip}` 在运行时替换为实际出口 IP）
/// 主接口 ipapi.is 返回是否机房(is_datacenter)、代理(is_proxy/is_vpn)、滥用评分(abuser_score)
pub const IP_RISK_PRIMARY_TEMPLATE: &str = "https://api.ipapi.is/?q={ip}";
/// 备接口 ip-api.com 返回 hosting(机房) / proxy(公开代理) / mobile / as 等属性
pub const IP_RISK_FALLBACK_TEMPLATE: &str =
    "http://ip-api.com/json/{ip}?fields=status,message,countryCode,isp,org,as,hosting,proxy,mobile";

/// 风险分告警阈值（0~100 分，越低越纯净；高于此阈值亮黄灯提示风控风险）
pub const IP_RISK_WARN_THRESHOLD: u32 = 45;

/// [04 Claude 可访问性] 检测目标地址与官方下载引导地址
pub const CLAUDE_WEB_URL: &str = "https://claude.ai";
pub const BRAVE_DOWNLOAD_URL: &str = "https://brave.com/download/";

/// [05 DNS 泄露检测] 免 Key 权威递归 DNS 出口探测后缀
/// 请求 `https://<32位随机字符>.edns.ip-api.com/json` 将返回实际发起递归解析的 DNS 服务器 IP 与国家
pub const DNS_LEAK_EDNS_DOMAIN_SUFFIX: &str = "edns.ip-api.com";
/// 本机直连常见境内公共/运营商 DNS 所在地区码（代理指向海外但递归 DNS 仍在境内时判定为 DNS 泄露）
pub const LOCAL_ISP_DNS_COUNTRY_CODES: &[&str] = &["CN"];
