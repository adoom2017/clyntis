pub mod import;
pub mod profiles;
pub mod protocol;
pub mod settings;

use anyhow::{Result, ensure};
use std::{fs, io::Write, path::Path};

pub const CONFIG_LIMIT: usize = 24 * 1024 * 1024;

/// Write in the destination directory so replacement is atomic on both platforms.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "文件超过大小限制");
    Ok(bytes)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Logs are untrusted text. Never export URL credentials/query strings or UUIDs.
pub fn redact(text: &str) -> String {
    use std::sync::LazyLock;
    static URL: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"(?i)(?:https?|vless)://[^\s\"<>]+"#).unwrap());
    static UUID: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b").unwrap()
    });
    static BEARER: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"(?i)\bBearer\s+[^\s,"}]+"#).unwrap());
    static SECRET: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)((?:"|')?(?:password|secret|token|authorization|uuid)(?:"|')?)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)"#).unwrap()
    });
    let text = BEARER.replace_all(text, "Bearer [已隐藏]");
    SECRET
        .replace_all(
            &UUID.replace_all(&URL.replace_all(&text, "[URL 已隐藏]"), "[UUID 已隐藏]"),
            "$1$2[已隐藏]",
        )
        .into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn atomic_write_replaces_existing_file_in_unicode_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("配置 files").join("settings.json");
        super::atomic_write(&path, b"original").unwrap();
        super::atomic_write(&path, "更新".as_bytes()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "更新");
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn log_redaction_hides_authorization_json_fields_urls_and_uuid() {
        let output = super::redact(
            r#"Authorization: Bearer abcdef123 password=private "secret":"hidden" https://example.com/sub?token=private 11111111-1111-4111-8111-111111111111"#,
        );
        for secret in ["abcdef123", "private", "hidden", "example.com", "11111111"] {
            assert!(!output.contains(secret), "{output}");
        }
    }
}
