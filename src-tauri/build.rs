fn main() {
    tauri_build::build();

    // Windows MinGW (GNU) 工具链兼容处理：
    // 1. 仅对 cdylib 关闭默认全量自动导出，避免 debug 模式超过 PE 导出表 65535 上限；
    // 2. 为 tests/ 集成测试二进制注入含 Common-Controls v6 Manifest 的 libresource.a。
    #[cfg(all(target_os = "windows", target_env = "gnu"))]
    {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-all-symbols");
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            let res_archive = std::path::Path::new(&out_dir).join("libresource.a");
            if res_archive.exists() {
                println!("cargo:rustc-link-arg-tests={}", res_archive.display());
            }
        }
    }
}
