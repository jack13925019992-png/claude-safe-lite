# 双端发版运维与客户安装放行标准手册（Windows & macOS）

本文档提供 **GitHub 私有仓库代码推送、双端自动打包触发** 以及 **面向 Windows / Mac 终端客户的标准客服指引**。

- **私有仓库地址**：`https://github.com/jack13925019992-png/claude-safe-lite.git`
- **安全隔离机制**：`.gitignore` 与云端 GitHub Actions 安全门禁双重排除 `admin-license-issuer/`、`cloud-license-worker/`、`issuer-config.json` 及一切私钥文件，确保云端仓库与安装包 100% 仅含纯客户端代码。

---

## 一、管理员日常更新与触发云端双端打包（1-2-3 步）

1. **保存修改并核验状态**（在 `Claude-Safe-Lite` 项目目录打开 PowerShell）：
   ```powershell
   git status
   git add .
   git commit -m "update: 更新客户端功能"
   ```
2. **推送代码并打上 `v*` 正式版本标签触发云端打包**（将 `v2.0.1` 替换为新版本号；注：仅 `git push origin main` 只保存代码不触发打包，推送 `v*` 标签或网页点击 `Run workflow` 才会触发完整双端编译与 Release 发布，避免重复计费）：
   ```powershell
   git push origin main
   git tag v2.0.1
   git push origin v2.0.1
   ```
3. **查看构建进度与获取双端安装包**：
   - 打开仓库 **Actions** 页面：`https://github.com/jack13925019992-png/claude-safe-lite/actions`（Windows 与 macOS 任务并行运行，约 5~9 分钟变成绿勾 `✓`）；
   - 打开仓库 **Releases** 页面：`https://github.com/jack13925019992-png/claude-safe-lite/releases`，即可同时下载：
     - Windows 安装版：`Claude-Safe-Lite_v*_Windows_x64_Setup.exe`
     - Windows 单文件绿色版：`Claude-Safe-Lite_v*_Windows_x64_Portable.exe`
     - macOS 通用版（M芯片+Intel二合一）：`Claude-Safe-Lite_v*_macOS_Universal.dmg`

> **提示（本地离线打包备选）**：如需在 Windows 开发机本地离线打包单文件绿色版，直接双击或执行根目录下的 `build-release.cmd` 即可生成至 `release-portable\claude-safe-lite.exe`（已被 `.gitignore` 自动忽略，不会污染仓库）。

---

## 二、客服快捷回复模板（无冗余、可直接复制发微信）

### 模板 A：发给微软 Windows 客户

```text
💻 Claude安全客户端（Windows 版）首次使用 3 步说明

1. 双击运行发给您的安装包（Setup.exe 为向导安装版，Portable.exe 为免安装直接运行版）。

2. 解除 Windows 首次运行蓝屏拦截（仅第一次打开需要）：
   若弹出蓝色提示框“Windows 已保护你的电脑”：
   ① 点击提示文字下方的【更多信息】；
   ② 点击右下角出现的【仍要运行】按钮即可正常打开。
   （若电脑装有 360/火绒弹窗询问网络或创建浏览器进程，请点击“允许”放行。）

3. 首次登录激活：
   填入您的【姓名 + 手机号 + 授权码（CL-开头）】并粘贴 SOCKS5 代理链接，点击【校验并进入客户端】（注意：授权码首次登录即自动绑定本台电脑，转发其他电脑无效）。检测亮绿灯后点击【启动安全浏览器访问 Claude】即可安全使用。
```

### 模板 B：发给苹果 macOS 客户（M1~M4 芯片与 Intel 通用）

```text
🍎 Claude安全客户端（Mac 通用版）首次使用 3 步说明

1. 双击下载的 .dmg 安装包，将窗口中的【Claude Safe Lite】图标拖拽到右侧【Applications（应用程序）】文件夹。

2. 解除苹果系统首次打开拦截（仅第一次打开需要，之后直接双击秒开）：
   ① 在【应用程序】中双击打开 Claude Safe Lite，若弹出“无法验证开发者”，先点【完成】或【取消】关闭弹窗；
   ② 打开苹果电脑【系统设置】→ 左侧点击【隐私与安全性】；
   ③ 往下拉到页面最底部，找到“已阻止使用 Claude Safe Lite”，点击右侧【仍要打开】并验证开机密码或指纹即可。

   💡 备用方法（若个别系统提示“软件已损坏，无法打开”）：
   打开电脑自带的【终端 (Terminal)】，复制下面这一整行命令粘贴进去按回车，输入开机密码（输入时不显示星号，输完直接按回车）即可一键解除：
   sudo xattr -rd com.apple.quarantine "/Applications/Claude Safe Lite.app"

3. 首次登录激活：
   填入您的【姓名 + 手机号 + 授权码（CL-开头）】并粘贴 SOCKS5 代理链接，点击【校验并进入客户端】（授权码首次登录即自动绑定本台 Mac，转发无效）。检测亮绿灯后点击【启动安全浏览器访问 Claude】即可安全使用。
```
