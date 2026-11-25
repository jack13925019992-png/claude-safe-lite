# Claude Safe Lite v2（Windows & macOS 双平台客户端）

**Claude安全客户端（Claude Safe Lite v2）** 是一款支持 **Windows 10/11 (x64)** 与 **macOS (Apple Silicon M1~M4 / Intel 通用)** 的独立环境隔离与 SOCKS5 安全代理链路守护工具。

---

## 一、核心安全特性

1. **云端一机一码与 Ed25519 验签保护**：首次输入授权码自动绑定当前电脑主板硬件识别码（Windows `MachineGuid` / macOS `IOPlatformUUID`），云端响应经 Ed25519 公钥验签与本机硬件级加密落盘，转发第二台电脑立即拦截。
2. **本地回环转发器（Forwarder）**：严格绑定 `127.0.0.1:0`，统一承接带用户名/密码（RFC 1929）的静态住宅 SOCKS5 代理，域名强制 `ATYP=0x03` 远端透传解析，零本地 DNS 泄露。
3. **五项环境预检仪表盘**：自动检测「01 代理连接 → 02 出口 IP 国家 → 03 IP 风险评分 → 04 Claude 可访问 → 05 DNS 泄露」，关键阻断项未通过时禁止直连裸奔。
4. **安全浏览器隔离沙箱与掉线秒级熔断（Kill Switch）**：
   - 自动按 **Brave → Chrome** 顺序探测（每套代理拥有独立 Profile 目录，Cookie 互不串号），注入禁用 QUIC / WebRTC 非代理 UDP / 本地 DNS 规则；
   - 后台双引擎实时巡检，一旦检测到出口 IP 突变、DNS 泄露或代理掉线，毫秒级切断本地转发器并通过系统级沙箱（Windows `Job Object` / macOS 独立进程组 `PGID`）精准终止安全浏览器进程树，**绝不误杀用户自己打开的日常浏览器窗口**。
5. **扩展工具代理一键注入**：支持一键拉起带安全代理环境的 `Claude Code (CLI)` 独立终端与 `Claude` 官方桌面客户端。

---

## 二、GitHub Releases 安装包下载选型

打开本仓库右侧 **[Releases](https://github.com/jack13925019992-png/claude-safe-lite/releases)** 页面下载对应系统安装包：

| 操作系统 | 推荐下载文件 | 适用说明 |
| :--- | :--- | :--- |
| **Windows 10 / 11 (64位)** | `Claude-Safe-Lite_v*_Windows_x64_Setup.exe` | **推荐普通客户**：一键安装向导，自动创建桌面与开始菜单快捷方式 |
| **Windows 10 / 11 (免安装)** | `Claude-Safe-Lite_v*_Windows_x64_Portable.exe` | **单文件绿色版**：无需安装，放入任意文件夹双击直接运行 |
| **macOS (M 芯片 & Intel 通用)** | `Claude-Safe-Lite_v*_macOS_Universal.dmg` | **双架构二合一**：同时原生兼容 Apple Silicon (M1/M2/M3/M4) 与 Intel Mac |

---

## 三、发给客户的「首次安装与解除拦截指引」（可直接复制发送）

### 💻 发给 Windows 客户的 1-2-3 安装说明

```text
💻 Claude安全客户端（Windows 版）安装与启动说明

1. 下载安装包（Setup.exe 安装版或 Portable.exe 免安装版），双击运行。

2. 首次打开解除微软蓝屏安全提示（仅第一次运行需要）：
   若弹出蓝色窗口提示“Windows 已保护你的电脑（Microsoft Defender SmartScreen 已阻止启动未识别的应用）”：
   ① 点击弹窗文字下方的【更多信息】（带下划线的小字）；
   ② 点击窗口右下角新出现的【仍要运行】按钮，即可正常安装并进入软件。

3. 打开软件后，依次填写您的【姓名 + 手机号 + 授权码】以及 SOCKS5 代理信息，点击【校验并进入客户端】，待五盏安全检测灯通过后点击【启动安全浏览器访问 Claude】即可。
```

### 🍎 发给 Mac 客户的 1-2-3 安装说明

```text
🍎 Claude安全客户端（Mac 版 · M芯片与Intel通用）安装与启动说明

1. 双击下载的 .dmg 安装包，在弹出的窗口中将【Claude Safe Lite】图标拖拽到右侧【Applications（应用程序）】文件夹内。

2. 首次打开解除苹果系统拦截（仅第一次打开需要，之后直接双击秒开）：
   ① 打开【应用程序】文件夹，双击 Claude Safe Lite，若弹出“无法验证开发者”提示，先点击【完成】或【取消】关闭弹窗；
   ② 打开苹果电脑【系统设置】→ 左侧点击【隐私与安全性】；
   ③ 拉到页面最底部，找到“已阻止使用 Claude Safe Lite”，点击右侧【仍要打开】，输入电脑开机密码或指纹即可放行。

   （注：如遇个别系统直接提示“软件已损坏，无法打开”，请打开电脑自带的【终端 / Terminal】，复制粘贴以下一整行命令按回车，输入开机密码后回车即可一键永久解除：
   sudo xattr -rd com.apple.quarantine "/Applications/Claude Safe Lite.app" ）

3. 进入软件后，填写您的【姓名 + 手机号 + 授权码】以及 SOCKS5 代理信息，点击【校验并进入客户端】，待检测通过后点击【启动安全浏览器访问 Claude】即可。
```

---

## 四、开发者维护与云端自动打包说明

本项目已配置 GitHub Actions 双端自动构建流水线（[`.github/workflows/release.yml`](.github/workflows/release.yml)）。为避免日常普通提交与版本标签重复触发、节省构建配额，**仅在推送 `v*` 版本标签（或网页端手动点击 `Run workflow`）时执行完整双端打包并自动发布至 GitHub Releases**：

1. **平时保存并推送代码到主分支（不消耗打包配额）**：
   ```powershell
   git add .
   git commit -m "update: 优化客户端体验"
   git push origin main
   ```
2. **需要打包发布新版本时（打上 `v*` 标签推送，自动编译 Windows + macOS 并发布 Release）**：
   ```powershell
   git tag v2.0.1
   git push origin v2.0.1
   ```

更多详细发版步骤与架构文档请参阅 [`docs/`](docs/) 目录。
