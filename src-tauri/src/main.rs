// 阻止 Windows Release 模式下弹出额外的控制台黑框（需求 5.8 / 12.1）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(all(target_os = "windows", target_env = "gnu"))]
    claude_safe_lite_lib::wv2_embedded::anchor_embedded_webview2_loader();

    claude_safe_lite_lib::run()
}
