//! 本机当前用户作用域安全加解密模块（Windows DPAPI / macOS 硬件与账户绑定 AES-256-GCM）
//!
//! 安全铁律（Fail-Closed）：
//! - Windows 平台调用原生 `CryptProtectData`（`CRYPTPROTECT_UI_FORBIDDEN`）加密明文并输出标准 Base64；
//! - macOS / Unix 平台基于「本机硬件平台 UUID + 当前系统 UID」经 HMAC-SHA256 派生本机专属密钥，
//!   采用 `AES-256-GCM` 认证加密（AEAD），既保证跨机拷贝自动失效，又避免未公证应用反复弹出系统钥匙串授权框；
//! - 任何加解密失败或密文篡改一律返回明确错误并拒绝保存/使用，严禁降级为明文存储或按明文回退。

use thiserror::Error;

/// 本机凭据加解密错误定义（错误信息中严禁包含任何明文或原始密文）
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("待加密密码不能为空")]
    EmptyPlaintext,
    #[error("密文数据为空")]
    EmptyCiphertext,
    #[error("密文 Base64 格式损坏或非法")]
    InvalidBase64,
    #[error("系统本机安全加密调用失败 (Code: {0})")]
    DpapiProtectFailed(u32),
    #[error("系统本机安全解密失败，可能跨设备/跨用户迁移或密文已损坏 (Code: {0})")]
    DpapiUnprotectFailed(u32),
    #[error("解密后的密码非合法 UTF-8 编码")]
    InvalidUtf8,
}

// ============================================================================
// Windows 原生实现：DPAPI (CryptProtectData / CryptUnprotectData)
// ============================================================================
#[cfg(windows)]
mod imp {
    use std::ptr;

    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::CryptoError;

    pub fn encrypt(plaintext: &str) -> Result<String, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::EmptyPlaintext);
        }

        let mut input_bytes = plaintext.as_bytes().to_vec();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: input_bytes.len() as u32,
            pbData: input_bytes.as_mut_ptr(),
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY: in_blob 指向有效连续字节切片，out_blob 由系统分配并在下方通过 LocalFree 释放
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        // 主动擦除临时明文副本
        input_bytes.fill(0);

        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(CryptoError::DpapiProtectFailed(code));
        }

        if out_blob.pbData.is_null() || out_blob.cbData == 0 {
            if !out_blob.pbData.is_null() {
                unsafe {
                    LocalFree(out_blob.pbData as _);
                }
            }
            return Err(CryptoError::DpapiProtectFailed(0));
        }

        let encrypted_slice =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        let encoded = BASE64_STD.encode(encrypted_slice);

        unsafe {
            LocalFree(out_blob.pbData as _);
        }

        Ok(encoded)
    }

    pub fn decrypt(ciphertext_b64: &str) -> Result<String, CryptoError> {
        let trimmed = ciphertext_b64.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::EmptyCiphertext);
        }

        let mut raw_cipher = BASE64_STD
            .decode(trimmed)
            .map_err(|_| CryptoError::InvalidBase64)?;
        if raw_cipher.is_empty() {
            return Err(CryptoError::EmptyCiphertext);
        }

        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: raw_cipher.len() as u32,
            pbData: raw_cipher.as_mut_ptr(),
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // SAFETY: in_blob 指向有效密文字节切片，out_blob 内存拷贝后立即清零并由 LocalFree 释放
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(CryptoError::DpapiUnprotectFailed(code));
        }

        if out_blob.pbData.is_null() {
            return Err(CryptoError::DpapiUnprotectFailed(0));
        }

        let decrypted_bytes = unsafe {
            let slice = std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize);
            let vec_copy = slice.to_vec();
            // 擦除系统缓冲区中的明文残留
            slice.fill(0);
            LocalFree(out_blob.pbData as _);
            vec_copy
        };

        String::from_utf8(decrypted_bytes).map_err(|err| {
            let mut raw = err.into_bytes();
            raw.fill(0);
            CryptoError::InvalidUtf8
        })
    }
}

// ============================================================================
// macOS / Unix 原生实现：硬件 UUID + 当前用户 UID 绑定 AES-256-GCM (AEAD)
// ============================================================================
#[cfg(not(windows))]
mod imp {
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    use ring::hmac::{self, HMAC_SHA256};
    use ring::rand::{SecureRandom, SystemRandom};

    use super::CryptoError;

    const BLOB_MAGIC: &[u8; 4] = b"CSL2";
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    const AAD_CONTEXT: &[u8] = b"ClaudeSafeLite-v2-LocalBoundVault";
    const KDF_SALT: &[u8] = b"CSL-V2-MACOS-DEVICE-USER-KDF-2026";

    fn derive_device_user_key() -> Result<LessSafeKey, CryptoError> {
        let hw_seed = crate::license::raw_hardware_identity_seed();
        let uid = unsafe { libc::getuid() };
        let mut ikm = format!("CSL-LOCAL-VAULT|uid={}|hw={}", uid, hw_seed).into_bytes();

        let salt_key = hmac::Key::new(HMAC_SHA256, KDF_SALT);
        let tag = hmac::sign(&salt_key, &ikm);
        ikm.fill(0);

        let unbound = UnboundKey::new(&AES_256_GCM, tag.as_ref())
            .map_err(|_| CryptoError::DpapiProtectFailed(1))?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn encrypt(plaintext: &str) -> Result<String, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::EmptyPlaintext);
        }

        let key = derive_device_user_key()?;
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::DpapiProtectFailed(2))?;

        let mut in_out = plaintext.as_bytes().to_vec();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        if key
            .seal_in_place_append_tag(nonce, Aad::from(AAD_CONTEXT), &mut in_out)
            .is_err()
        {
            in_out.fill(0);
            return Err(CryptoError::DpapiProtectFailed(3));
        }

        let mut blob = Vec::with_capacity(BLOB_MAGIC.len() + NONCE_LEN + in_out.len());
        blob.extend_from_slice(BLOB_MAGIC);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);
        in_out.fill(0);

        Ok(BASE64_STD.encode(&blob))
    }

    pub fn decrypt(ciphertext_b64: &str) -> Result<String, CryptoError> {
        let trimmed = ciphertext_b64.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::EmptyCiphertext);
        }

        let mut raw_blob = BASE64_STD
            .decode(trimmed)
            .map_err(|_| CryptoError::InvalidBase64)?;
        if raw_blob.is_empty() {
            return Err(CryptoError::EmptyCiphertext);
        }

        let min_len = BLOB_MAGIC.len() + NONCE_LEN + TAG_LEN + 1;
        if raw_blob.len() < min_len || &raw_blob[..4] != BLOB_MAGIC {
            raw_blob.fill(0);
            return Err(CryptoError::DpapiUnprotectFailed(1));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&raw_blob[4..4 + NONCE_LEN]);
        let mut cipher_and_tag = raw_blob[4 + NONCE_LEN..].to_vec();
        raw_blob.fill(0);

        let key = derive_device_user_key()?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let plain_slice = match key.open_in_place(
            nonce,
            Aad::from(AAD_CONTEXT),
            &mut cipher_and_tag,
        ) {
            Ok(s) => s,
            Err(_) => {
                cipher_and_tag.fill(0);
                return Err(CryptoError::DpapiUnprotectFailed(2));
            }
        };

        let plain_vec = plain_slice.to_vec();
        cipher_and_tag.fill(0);

        String::from_utf8(plain_vec).map_err(|err| {
            let mut raw = err.into_bytes();
            raw.fill(0);
            CryptoError::InvalidUtf8
        })
    }
}

/// 使用当前系统登录用户的本机绑定密钥加密密码，返回 Base64 密文
pub fn dpapi_encrypt(plaintext: &str) -> Result<String, CryptoError> {
    imp::encrypt(plaintext)
}

/// 解密由 `dpapi_encrypt` 生成的 Base64 密文，还原明文密码（仅在后端内存瞬时使用）
pub fn dpapi_decrypt(ciphertext_b64: &str) -> Result<String, CryptoError> {
    imp::decrypt(ciphertext_b64)
}
