//! Windows GNU 单文件绿色版核心垫片：编译期静态内嵌官方 `WebView2Loader.dll`
//!
//! 背景：
//! `webview2-com-sys` 在 MSVC 下静态链接 `WebView2LoaderStatic.lib`，而在 GNU 工具链下默认动态链接 `WebView2Loader.dll`，
//! 导致单独拷贝 `claude-safe-lite.exe` 到其他目录双击时提示“找不到 WebView2Loader.dll”。
//!
//! 方案：
//! 在 Rust 主编译单元中直接定义 WebView2Loader 的 4 个导出符号及其 `__imp_*` 导入表指针（链接顺序先于 `-lWebView2Loader.dll`，
//! 使 GNU `ld` 完全不从外部导入库提取任何动态导入项），首次调用时按需释放并加载内嵌的微软官方签名 `WebView2Loader.dll`。

use core::ffi::c_void;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

const WV2_DLL_BYTES: &[u8] = include_bytes!("../vendor/x64/WebView2Loader.dll");
const WV2_CACHE_FILE_NAME: &str = "WebView2Loader_v0_39_1_x64.dll";
const E_FAIL_HRESULT: i32 = -2147467259i32; // 0x80004005

type FnCreateEnvWithOptions = unsafe extern "system" fn(
    browser_executable_folder: *const u16,
    user_data_folder: *const u16,
    environment_options: *mut c_void,
    environment_created_handler: *mut c_void,
) -> i32;

type FnCreateEnv = unsafe extern "system" fn(environment_created_handler: *mut c_void) -> i32;

type FnGetAvailableVersion = unsafe extern "system" fn(
    browser_executable_folder: *const u16,
    version_info: *mut *mut u16,
) -> i32;

type FnCompareVersions =
    unsafe extern "system" fn(version1: *const u16, version2: *const u16, result: *mut i32) -> i32;

struct Wv2DispatchTable {
    create_with_options: FnCreateEnvWithOptions,
    create_env: FnCreateEnv,
    get_version: FnGetAvailableVersion,
    compare_versions: FnCompareVersions,
}

static WV2_TABLE: OnceLock<Option<Wv2DispatchTable>> = OnceLock::new();

fn to_wide_z(p: &Path) -> Vec<u16> {
    OsStr::new(p)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

unsafe fn try_load_module(path: &Path) -> HMODULE {
    let wide = to_wide_z(path);
    LoadLibraryW(wide.as_ptr())
}

fn ensure_runtime_dll_path() -> Option<PathBuf> {
    // 1. 若同级目录已存在 WebView2Loader.dll，优先就地使用
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let sibling = exe_dir.join("WebView2Loader.dll");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }

    // 2. 单文件绿色版模式：释放到 %LOCALAPPDATA%\ClaudeSafeLite\runtime\（回退 temp_dir）
    let base_dir = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("ClaudeSafeLite")
        .join("runtime");

    let _ = fs::create_dir_all(&base_dir);
    let target_dll = base_dir.join(WV2_CACHE_FILE_NAME);

    let already_valid = fs::metadata(&target_dll)
        .map(|m| m.is_file() && m.len() == WV2_DLL_BYTES.len() as u64)
        .unwrap_or(false);

    if !already_valid {
        let tmp_dll = base_dir.join(format!("wv2_{}.tmp", std::process::id()));
        if fs::write(&tmp_dll, WV2_DLL_BYTES).is_ok() {
            if fs::rename(&tmp_dll, &target_dll).is_err() {
                let _ = fs::remove_file(&tmp_dll);
            }
        }
    }

    if target_dll.is_file() {
        Some(target_dll)
    } else {
        None
    }
}

fn get_dispatch_table() -> Option<&'static Wv2DispatchTable> {
    WV2_TABLE
        .get_or_init(|| {
            let dll_path = ensure_runtime_dll_path()?;
            unsafe {
                let hmod = try_load_module(&dll_path);
                if hmod.is_null() {
                    return None;
                }

                let p_create_opts = GetProcAddress(
                    hmod,
                    b"CreateCoreWebView2EnvironmentWithOptions\0".as_ptr(),
                )?;
                let p_create =
                    GetProcAddress(hmod, b"CreateCoreWebView2Environment\0".as_ptr())?;
                let p_ver = GetProcAddress(
                    hmod,
                    b"GetAvailableCoreWebView2BrowserVersionString\0".as_ptr(),
                )?;
                let p_cmp = GetProcAddress(hmod, b"CompareBrowserVersions\0".as_ptr())?;

                Some(Wv2DispatchTable {
                    create_with_options: core::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCreateEnvWithOptions,
                    >(p_create_opts),
                    create_env: core::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCreateEnv,
                    >(p_create),
                    get_version: core::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnGetAvailableVersion,
                    >(p_ver),
                    compare_versions: core::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnCompareVersions,
                    >(p_cmp),
                })
            }
        })
        .as_ref()
}

#[no_mangle]
pub unsafe extern "system" fn CreateCoreWebView2EnvironmentWithOptions(
    browser_executable_folder: *const u16,
    user_data_folder: *const u16,
    environment_options: *mut c_void,
    environment_created_handler: *mut c_void,
) -> i32 {
    match get_dispatch_table() {
        Some(t) => (t.create_with_options)(
            browser_executable_folder,
            user_data_folder,
            environment_options,
            environment_created_handler,
        ),
        None => E_FAIL_HRESULT,
    }
}

#[no_mangle]
pub unsafe extern "system" fn CreateCoreWebView2Environment(
    environment_created_handler: *mut c_void,
) -> i32 {
    match get_dispatch_table() {
        Some(t) => (t.create_env)(environment_created_handler),
        None => E_FAIL_HRESULT,
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetAvailableCoreWebView2BrowserVersionString(
    browser_executable_folder: *const u16,
    version_info: *mut *mut u16,
) -> i32 {
    match get_dispatch_table() {
        Some(t) => (t.get_version)(browser_executable_folder, version_info),
        None => E_FAIL_HRESULT,
    }
}

#[no_mangle]
pub unsafe extern "system" fn CompareBrowserVersions(
    version1: *const u16,
    version2: *const u16,
    result: *mut i32,
) -> i32 {
    match get_dispatch_table() {
        Some(t) => (t.compare_versions)(version1, version2, result),
        None => E_FAIL_HRESULT,
    }
}

#[repr(transparent)]
pub struct SyncPtr(pub *const c_void);
unsafe impl Sync for SyncPtr {}

#[used]
#[no_mangle]
pub static __imp_CreateCoreWebView2EnvironmentWithOptions: SyncPtr =
    SyncPtr(CreateCoreWebView2EnvironmentWithOptions as *const c_void);

#[used]
#[no_mangle]
pub static __imp_CreateCoreWebView2Environment: SyncPtr =
    SyncPtr(CreateCoreWebView2Environment as *const c_void);

#[used]
#[no_mangle]
pub static __imp_GetAvailableCoreWebView2BrowserVersionString: SyncPtr =
    SyncPtr(GetAvailableCoreWebView2BrowserVersionString as *const c_void);

#[used]
#[no_mangle]
pub static __imp_CompareBrowserVersions: SyncPtr =
    SyncPtr(CompareBrowserVersions as *const c_void);

/// 供 `main.rs` 显式调用，确保在 Release `thin LTO` 阶段主编译单元最先锚定内嵌符号
#[inline(never)]
pub fn anchor_embedded_webview2_loader() {
    core::hint::black_box(&__imp_CreateCoreWebView2EnvironmentWithOptions);
    core::hint::black_box(&__imp_CreateCoreWebView2Environment);
    core::hint::black_box(&__imp_GetAvailableCoreWebView2BrowserVersionString);
    core::hint::black_box(&__imp_CompareBrowserVersions);
}
