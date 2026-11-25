# Claude Safe Lite v2 架构与工程交付报告（Windows & macOS 双平台版）

> **版本演进说明**：本项目在完成 Windows 11 x64 基础架构交付后，已全面升级支持 **云端 Ed25519 一机一码授权核销体系**、**新版 MSIX / macOS 官方 Claude 桌面端代理注入** 以及 **macOS (Apple Silicon + Intel Universal) 原生跨平台支持**。双端安装与日常发版指引请以根目录 `README.md` 为准。

## 1. 交付产物与构建验证摘要

本地 `build-release.cmd` 与云端 GitHub Actions 双端打包流水线（`.github/workflows/release.yml`）均已就绪，各项红线指标核验通过：

| 产物 / 配置项 | 构建方式 / 状态 | 说明 |
| --- | --- | --- |
| **Windows 单文件绿色版主程序** | 本地 `release-portable/claude-safe-lite.exe` / 云端 `*_Windows_x64_Portable.exe` | 开启 `windows_subsystem = "windows"` 无黑框；MinGW 下通过 `wv2_embedded.rs` 静态内嵌官方签名 `WebView2Loader.dll`，MSVC 下原生静态链接，**单文件任意拷贝双击即用，零外部 DLL 依赖** |
| **Windows NSIS / MSI 安装包** | 云端与本地 `bundle/nsis/*setup.exe`、`bundle/msi/*.msi` | 一键安装向导，自动创建桌面与开始菜单快捷方式 |
| **macOS 双架构通用安装包** | 云端 `Claude-Safe-Lite_v2.0.0_macOS_Universal.dmg` | `universal-apple-darwin` 编译（同时含 `arm64` M系列芯片与 `x86_64` Intel 芯片指令集），内置 Ad-hoc 签名 |
| **本地构建监控日志** | `build-logs/build-release-*.log` | 完整记录固定 PATH、编译前内存水位检查、编译期物理内存采样及打包日志 |
| **Cargo 红线核验** | `lto = "thin"`、`codegen-units = 4`、`crate-type = ["staticlib", "cdylib", "rlib"]` | 严格保留未篡改，全程基于 `x86_64-pc-windows-gnu` (MinGW64) 编译链接通过 |
| **自动化测试** | 阶段 1–3 共 **13 项单元与集成测试 100% 通过**；前端 `tsc --noEmit` 与 `vite build` **0 错误 0 警告** | 覆盖 DPAPI、日志脱敏轮转、代理粘贴解析、RFC 1929、域名透传、HTTP CONNECT 嗅探、`trip()` 断流、五项检测联动、Job Object 精准强杀与 Watchdog 防误报状态机 |

---

## 2. Rust Crate 依赖清单（含 v1 本地缓存核验）

严格遵循文档第 0.4 节「依赖克制原则」，优先复用本机 `.cargo\registry\cache` 已缓存的 v1 依赖版本，全量直接依赖如下：

| Crate 名称与版本 | 核心用途 | 是否已在 v1 缓存 |
| --- | --- | :---: |
| `tauri = "2"` (2.12.7, feature: `tray-icon`) | 桌面应用框架与内置系统托盘支持（`tray-icon` 0.25.1 已在缓存） | ✅ 是 |
| `tauri-build = "2"` (2.7.6) | Tauri 构建期代码与资源生成 | ✅ 是 |
| `tokio = "1"` (1.54.1) | 异步运行时（Forwarder 并发隧道、超时控制、后台巡检） | ✅ 是 |
| `tokio-util = "0.7"` (0.7.20) | 提供 `CancellationToken` 实现检测防抖取消与 `trip()` 毫秒级断流 | ✅ 是 |
| `reqwest = "0.12"` (0.12.28, `json`, `rustls-tls`, `socks`) | 五项检测与巡检 HTTP 客户端（`rustls-tls` 纯 Rust 免 OpenSSL 链接问题，强制经本地 `socks5h://` 代理发出） | ✅ 是 |
| `serde = "1"` / `serde_json = "1"` | 配置持久化与 Tauri IPC 数据序列化 | ✅ 是 |
| `windows-sys = "0.61"` (0.61.2) | Win32 原生 API 调用：DPAPI (`CryptProtectData`)、进程树隔离 (`JobObjects`)、注册表探测 (`Registry`)、进程/线程快照 (`ToolHelp`)、文件保存框 (`Dialogs`) | ✅ 是 |
| `uuid = "1"` (1.29.3) | 代理配置 UUID 生成与 EDNS 随机子域名防缓存标识 | ✅ 是 |
| `base64 = "0.22"` (0.22.1) | DPAPI 加密二进制 Blob 与 JSON 文本间的安全编码转换 | ✅ 是 |
| `chrono = "0.4"` (0.4.45) | 日志毫秒级本地时间戳与熔断触发时间格式化 | ✅ 是 |
| `dirs = "7"` (7.0.0) | 安全定位 `%APPDATA%` 与 `%USERPROFILE%`（原生支持非 ASCII 中文用户名） | ✅ 是 |
| `thiserror = "2"` / `anyhow = "1"` | 结构化错误枚举建模 | ✅ 是 |
| `url = "2"` (2.5.9) | 外部打开链接安全协议头 (`https://` / `http://`) 校验 | ✅ 是 |
| `tauri-plugin-notification = "2"` (2.8.1) | 需求文档 5.2 指定引入：安全熔断时推送 Windows 原生系统告警通知 | 🆕 v2 新增（文档指定） |
| `tauri-plugin-single-instance = "2"` (2.5.5) | 需求文档第 10 节要求：单实例运行保护，重复双击时自动唤醒聚焦已有主窗口 | 🆕 v2 新增（轻量插件） |

---

## 3. 核心架构、边缘情况 Fail-Closed 处理与文档对照说明

### 3.1 与需求文档的一致性及工程细节优化
1. **MinGW (GNU) 链接器兼容加固（`src-tauri/build.rs`）**：
   - **现象**：当 crate 包含 `cdylib` 且无显式 `dllexport` 符号时，MinGW `ld` 默认开启 `--export-all-symbols`，在未裁剪的 debug 模式下符号数超 PE 导出表 `65535` 上限；同时 `tauri-build` 默认仅对 `bins` 注入 Common-Controls v6 清单，导致集成测试进程加载旧版 `comctl32.dll` 缺失 `TaskDialogIndirect`。
   - **处理**：在不修改 `Cargo.toml` 红线参数的前提下，在 `build.rs` 中通过 Cargo 官方指令 `cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols` 与 `cargo:rustc-link-arg-tests=.../libresource.a` 精准解决，确保 `cargo check`、`cargo test` 与 `build-release.cmd` 全流程顺畅。
2. **集中式免 Key 检测 API 配置（`src-tauri/src/constants.rs`）**：
   - 因从零创建工程，已在 `constants.rs` 顶部集中封装带主备自动容灾的免 Key 公共检测接口：
     - **02 出口 IP 国家**：`ipwho.is` → `api.ip.sb/geoip` → `ipinfo.io/json`；
     - **03 IP 风险评分**：`api.ipapi.is`（识别机房 IDC、VPN、Proxy、Abuser）→ `ip-api.com`（识别 `hosting` / `proxy`）；
     - **04 Claude 可访问性**：`https://claude.ai`（识别 2xx/3xx 通过、403/429 及 `cf-mitigated: challenge` 拦截）；
     - **05 DNS 泄露检测**：`https://<随机32位>.edns.ip-api.com/json` 权威递归 DNS 出口探测。
   - 后续如需替换任意私有或商业 API，仅需修改 `constants.rs` 常量即可。

### 3.2 文档未显式展开的边缘情况（一律采用最保守 Fail-Closed 实现）
1. **DPAPI 加密或解密异常**：保存配置时若 `CryptProtectData` 失败，立即报错并拒绝落盘，绝不降级保存明文；读取或连接时若密文损坏或跨 Windows 账户迁移导致 `CryptUnprotectData` 失败，直接拒绝使用该配置并提示重新输入密码，绝不当作明文回退。
2. **`config.json` 与 `.bak` 双重损坏**：若主配置文件损坏，优先从有效 `.bak` 自动回退修复并在界面提示用户；若 `.bak` 同样损坏，按 Fail-Closed 初始化为空配置（默认开启安全模式），绝不崩溃或加载半截畸形配置。
3. **浏览器进程树零竞态绑定失败**：安全浏览器采用 `CREATE_SUSPENDED` 挂起创建主进程 → `AssignProcessToJobObject` 绑定开启 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的 Job Object → `ResumeThread` 恢复运行。若绑定或线程恢复任一步骤失败，立即 `kill` 挂起态子进程并返回错误，绝不允许不受 Job 管控的浏览器裸奔运行。
4. **熔断锁定态下的强制启动请求**：当 `Watchdog` 处于 `Tripped (locked == true)` 状态时，前端隐藏强制启动入口，且后端 `launch_browser(force: true)` 硬性拦截拒绝，必须经「重新检测」使关键项（01、02、04）全绿且无明确泄露后方可解锁。
5. **运行中修改/删除/切换激活代理**：当安全浏览器正在运行时，后端禁止切换激活代理、禁止修改或删除正在使用的代理配置、禁止执行「重置环境」，防止浏览器运行中途代理上下文错位。
6. **强制启动模式下的安全模式基线采样**：若用户在非熔断态使用「忽略检测，强制启动」且开启了安全模式，若尚无历史基线出口 IP，后台立即通过转发器异步采样建立基线；若连出口 IP 都无法经转发器获取，立即按掉线防直连规则触发熔断关闭浏览器。
7. **外部 URL 打开协议白名单**：`open_external` 命令严格校验仅允许 `https://` 与 `http://` 协议后调用 `ShellExecuteW`，阻断 `file://` 或命令注入风险。

---

## 4. 功能覆盖与后续扩展记录

- **P0 / P1 / P2 核心需求覆盖率**：初始架构文档定义的全部核心安全转发、五项预检、隔离沙箱与自动熔断功能均已 **100% 实现**。
- **跨平台与商业化增强项（已全部实装）**：
  1. **云端一机一码授权体系（`license.rs`）**：支持 `CL-XXXX-XXXX-XXXX-XXXX` 短授权码核销、Windows `MachineGuid` / macOS `IOPlatformUUID` 硬件指纹原子绑定，以及 Ed25519 数字签名防篡改校验；
  2. **双平台凭据安全存储（`crypto.rs`）**：Windows 采用 `DPAPI`，macOS 采用硬件 UUID + 系统账户 UID 绑定的 `AES-256-GCM` 认证加密；
  3. **Claude 桌面客户端全形态兼容（`tool_launcher.rs`）**：同时支持 Windows Squirrel 独立安装版、新版官方 MSIX (`WindowsApps\claude-desktop.exe`) 以及 macOS `/Applications/Claude.app` 的 `--proxy-server=socks5://127.0.0.1:<port>` 安全代理参数注入；
  4. **严格不做项保留**：不启用 Edge / Safari 浏览器、不支持明文密码落盘、不接管系统级全局/TUN 路由（保持纯应用级进程隔离）。

---

## 5. 需用户使用真实带认证 SOCKS5 代理实机验收清单

请在真机上使用您的**真实带用户名/密码（推荐含特殊字符）的静态住宅 SOCKS5 代理**逐项核验以下场景：

1. **无黑框启动与单实例唤醒**：
   - 双击运行安装包安装后（或直接运行 `src-tauri\target\release\claude-safe-lite.exe`），确认无黑框终端弹出；再次双击 exe 时自动唤醒并聚焦已有主窗口。
2. **快捷粘贴与 DPAPI 密文核验**：
   - 打开「代理管理 → 新增代理配置」，测试粘贴 `host:port:user:pass` 或 `socks5://user:pass@host:port`，点击「测试连接」与「保存配置」；
   - 打开 `%APPDATA%\ClaudeSafeLite\config.json` 与 `logs\*.log`，确认无任何密码明文，用户名在日志中显示为前 2 位 + `***`。
3. **五项检测与浏览器隔离启动**：
   - 观察主界面五盏灯逐项点亮及出口 IP / 国家 / 风险分展示；
   - 点击「启动安全浏览器访问 Claude」，确认优先拉起本机 Brave（未装 Brave 则拉起 Chrome），正常打开 `https://claude.ai`。
4. **防泄露与 `--host-resolver-rules` 兼容性实机确认（重点关注）**：
   - 浏览器已注入 `--disable-quic`、`--force-webrtc-ip-handling-policy=disable_non_proxied_udp` 与 `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`；
   - 请在安全浏览器中访问 IP / WebRTC / DNS 泄露测试页（如 `browserleaks.com/webrtc`、`ipleak.net`），验证显示代理出口 IP、无本机局域网/公网真实 IP 暴露、DNS 为海外远端解析，且 `claude.ai` 登录与对话流式响应正常无副作用。
5. **转发器端口回收验证**：
   - 关闭安全浏览器后，观察底部状态栏变为「本地转发器：已停止」，通过 `netstat -ano | findstr 127.0.0.1` 确认原随机转发端口已被立即释放。
6. **核心验收：掉线与泄露自动熔断（Kill Switch）**：
   - 先打开一个您日常使用的**普通 Brave/Chrome 窗口**，再通过本软件启动**安全浏览器**（确保顶部「安全模式」开启）；
   - 人为断开上游代理（或关闭上游节点），等待自动触发（或浏览器发起新请求触发即时联动）；
   - 验证软件自动完成：**切断转发器 → 强制关闭安全浏览器整个窗口进程树（且您自己打开的普通浏览器窗口完好无损！）→ 右下角弹出 Windows 原生告警通知 → 主界面顶部出现红色熔断锁定横幅且启动按钮置灰**；
   - 恢复上游代理后点击「立即重新检测」，验证关键项全绿后自动解除锁定并可重新启动。
7. **窗口关闭拦截与 Claude Code (CLI) 验证**：
   - 安全浏览器运行期间点击主窗口右上角 `×`，验证弹出「最小化到系统托盘（推荐）/ 彻底退出」选择框；
   - 若本机已安装 `@anthropic-ai/claude-code`，点击「启动 CLI」验证独立终端自动带代理环境启动。
