//! Tencent COS keys in the system keychain (macOS Keychain, Windows
//! Credential Manager): entered once in settings, never written to the
//! app's files or sent back to the webview.
use anyhow::{Context, Result};
use clyntis_core::cos::CosCredentials;

const SERVICE: &str = "org.clyntis.desktop.cos";

pub fn load() -> Result<Option<CosCredentials>> {
    let Some(bytes) = platform::read()? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(&bytes).context("钥匙串中的 COS 密钥无法读取，请重新填写")?,
    ))
}

pub fn store(credentials: &CosCredentials) -> Result<()> {
    platform::write(&serde_json::to_vec(credentials)?)
}

pub fn delete() -> Result<()> {
    platform::delete()
}

#[cfg(target_os = "macos")]
mod platform {
    use super::SERVICE;
    use anyhow::{Context, Result};
    use security_framework::passwords;

    const ACCOUNT: &str = "default";
    const NOT_FOUND: i32 = -25300; // errSecItemNotFound

    pub fn read() -> Result<Option<Vec<u8>>> {
        match passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.code() == NOT_FOUND => Ok(None),
            Err(error) => Err(error).context("无法读取钥匙串"),
        }
    }
    pub fn write(bytes: &[u8]) -> Result<()> {
        passwords::set_generic_password(SERVICE, ACCOUNT, bytes).context("无法写入钥匙串")
    }
    pub fn delete() -> Result<()> {
        match passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Err(error) if error.code() != NOT_FOUND => Err(error).context("无法删除钥匙串项目"),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::SERVICE;
    use anyhow::{Result, bail};
    use windows_sys::Win32::{
        Foundation::{ERROR_NOT_FOUND, GetLastError},
        Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
            CredReadW, CredWriteW,
        },
    };

    fn target() -> Vec<u16> {
        SERVICE.encode_utf16().chain([0]).collect()
    }

    pub fn read() -> Result<Option<Vec<u8>>> {
        let target = target();
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: target is NUL-terminated; CredReadW allocates `credential`,
        // which is freed with CredFree after its blob is copied.
        unsafe {
            if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) == 0 {
                if GetLastError() == ERROR_NOT_FOUND {
                    return Ok(None);
                }
                bail!("无法读取 Windows 凭据管理器（{}）", GetLastError());
            }
            let blob = std::slice::from_raw_parts(
                (*credential).CredentialBlob,
                (*credential).CredentialBlobSize as usize,
            )
            .to_vec();
            CredFree(credential.cast());
            Ok(Some(blob))
        }
    }
    pub fn write(bytes: &[u8]) -> Result<()> {
        let mut target = target();
        let mut blob = bytes.to_vec();
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: every pointer in `credential` outlives the call.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            bail!("无法写入 Windows 凭据管理器（{}）", unsafe {
                GetLastError()
            });
        }
        Ok(())
    }
    pub fn delete() -> Result<()> {
        let target = target();
        // SAFETY: target is NUL-terminated.
        unsafe {
            if CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) == 0
                && GetLastError() != ERROR_NOT_FOUND
            {
                bail!("无法删除 Windows 凭据（{}）", GetLastError());
            }
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    use anyhow::{Result, bail};
    pub fn read() -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    pub fn write(_: &[u8]) -> Result<()> {
        bail!("此平台不支持保存 COS 密钥")
    }
    pub fn delete() -> Result<()> {
        Ok(())
    }
}
