use crate::tr;
use crate::{CONFIG_LIMIT, atomic_write, now, private_dir, read_limited, settings::Settings};
use anyhow::{Context, Result, ensure};
use clyntis_config::{Config, ProxyKind};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

#[derive(Serialize)]
pub struct ImportResult {
    pub profile: ProfileSummary,
    pub warnings: Vec<crate::import::ImportWarning>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub url: Option<String>,
    pub yaml: String,
    pub pending: Option<String>,
    pub previous: Option<String>,
    pub last_checked: u64,
    pub last_error: Option<String>,
    pub mode: String,
    /// Password for encrypted subscriptions, kept so scheduled updates can decrypt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Where encrypted exports of this profile were last published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<PublishTarget>,
}

/// A Tencent COS object: `https://<bucket>.cos.<region>.myqcloud.com/<key>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishTarget {
    pub bucket: String,
    pub region: String,
    pub key: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    pub id: Uuid,
    pub name: String,
    pub source: String,
    pub subscription: bool,
    pub encrypted: bool,
    pub pending: bool,
    pub last_checked: u64,
    pub last_error: Option<String>,
}
impl Profile {
    pub fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            id: self.id,
            name: self.name.clone(),
            source: self
                .url
                .as_ref()
                .and_then(|s| reqwest::Url::parse(s).ok())
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_else(|| tr!("本地文件", "Local file")),
            subscription: self.url.is_some(),
            encrypted: self.password.is_some(),
            pending: self.pending.is_some(),
            last_checked: self.last_checked,
            last_error: self.last_error.clone(),
        }
    }
}

const MITM_CERT: &str = "mitm-ca.pem";
const MITM_KEY: &str = "mitm-ca.key";

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
}
impl Store {
    pub fn new(root: PathBuf) -> Result<Self> {
        private_dir(&root)?;
        private_dir(&root.join("profiles"))?;
        Ok(Self { root })
    }
    pub fn directory(&self, id: Uuid) -> PathBuf {
        self.root.join("profiles").join(id.to_string())
    }
    pub fn runtime_dir(&self, id: Uuid) -> PathBuf {
        self.directory(id).join("runtime")
    }
    pub fn list(&self) -> Result<Vec<ProfileSummary>> {
        let mut profiles = Vec::new();
        for entry in fs::read_dir(self.root.join("profiles"))? {
            let entry = entry?;
            if let Ok(id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) {
                profiles.push(self.get(id)?.summary());
            }
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }
    pub fn get(&self, id: Uuid) -> Result<Profile> {
        let path = self.directory(id).join("profile.json");
        serde_json::from_slice(&read_limited(&path, CONFIG_LIMIT * 3 + 65536)?).with_context(|| {
            tr!(
                "配置文件不是有效的 JSON：{}",
                "The profile file is not valid JSON: {}",
                path.display()
            )
        })
    }
    pub fn save(&self, profile: &Profile) -> Result<()> {
        validate(&profile.yaml)?;
        atomic_write(
            &self.directory(profile.id).join("profile.json"),
            &serde_json::to_vec(profile)?,
        )
    }
    pub fn create(
        &self,
        name: String,
        yaml: String,
        url: Option<String>,
        password: Option<String>,
    ) -> Result<Profile> {
        ensure!(
            !name.trim().is_empty() && name.len() <= 256,
            "{}",
            tr!(
                "配置名称不能为空且不能超过 256 字节",
                "The profile name must be 1–256 bytes"
            )
        );
        let config = validate(&yaml)?;
        if let Some(url) = &url {
            subscription_url(url)?;
        }
        let profile = Profile {
            id: Uuid::new_v4(),
            name: name.trim().into(),
            yaml,
            url,
            pending: None,
            previous: None,
            last_checked: now(),
            last_error: None,
            mode: serde_json::to_value(config.mode)?
                .as_str()
                .unwrap_or("rule")
                .into(),
            password,
            publish: None,
        };
        self.save(&profile)?;
        private_dir(&self.runtime_dir(profile.id))?;
        Ok(profile)
    }
    pub fn delete(&self, id: Uuid) -> Result<()> {
        self.get(id)?;
        fs::remove_dir_all(self.directory(id))?;
        Ok(())
    }
    pub fn settings(&self) -> Result<Settings> {
        let path = self.root.join("settings.json");
        if !path.exists() {
            return Ok(Settings::default());
        }
        let settings: Settings = serde_json::from_slice(&read_limited(&path, 65536)?)
            .with_context(|| {
                tr!(
                    "设置文件不是有效的 JSON：{}",
                    "The settings file is not valid JSON: {}",
                    path.display()
                )
            })?;
        settings.validate()?;
        Ok(settings)
    }
    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        atomic_write(
            &self.root.join("settings.json"),
            &serde_json::to_vec(settings)?,
        )
    }
    /// The HTTPS decryption CA (certificate and key, PEM), kept apart from
    /// the settings so the key never reaches the window.
    pub fn mitm_authority(&self) -> Result<Option<(String, String)>> {
        let (cert, key) = (self.root.join(MITM_CERT), self.root.join(MITM_KEY));
        if !cert.exists() || !key.exists() {
            return Ok(None);
        }
        Ok(Some((
            String::from_utf8(read_limited(&cert, 65536)?)?,
            String::from_utf8(read_limited(&key, 65536)?)?,
        )))
    }
    pub fn save_mitm_authority(&self, cert: &str, key: &str) -> Result<()> {
        // Temporary files are created owner-only, and keep that when renamed.
        atomic_write(&self.root.join(MITM_KEY), key.as_bytes())?;
        atomic_write(&self.root.join(MITM_CERT), cert.as_bytes())
    }
    /// The settings with the CA filled in, for the core.
    pub fn with_mitm_authority(&self, mut settings: Settings) -> Result<Settings> {
        if let Some(mitm) = settings.overrides.mitm.as_mut()
            && let Some((cert, key)) = self.mitm_authority()?
        {
            mitm.ca_cert = cert;
            mitm.ca_key = key;
        }
        Ok(settings)
    }
    /// Rules added in the app, applied before every profile's own rules.
    pub fn custom_rules(&self) -> Result<Vec<String>> {
        let path = self.root.join("custom-rules.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        serde_json::from_slice(&read_limited(&path, 1024 * 1024)?).with_context(|| {
            tr!(
                "自定义规则文件不是有效的 JSON：{}",
                "The custom rules file is not valid JSON: {}",
                path.display()
            )
        })
    }
    pub fn save_custom_rules(&self, rules: &[String]) -> Result<()> {
        ensure!(
            rules.len() <= clyntis_config::custom::MAX_RULES,
            "{}",
            tr!(
                "自定义规则不能超过 {} 条",
                "No more than {} custom rules",
                clyntis_config::custom::MAX_RULES
            )
        );
        let rules: Vec<String> = rules.iter().map(|r| r.trim().to_owned()).collect();
        for (i, rule) in rules.iter().enumerate() {
            clyntis_config::custom::validate(rule)
                .with_context(|| tr!("第 {} 条规则「{rule}」", "Rule {} “{rule}”", i + 1))?;
        }
        atomic_write(
            &self.root.join("custom-rules.json"),
            &serde_json::to_vec(&rules)?,
        )
    }
    pub fn selected(&self) -> Result<Option<Uuid>> {
        let path = self.root.join("selected.json");
        if !path.exists() {
            return Ok(None);
        }
        let id: Option<Uuid> =
            serde_json::from_slice(&read_limited(&path, 1024)?).with_context(|| {
                tr!(
                    "配置选择记录不是有效的 JSON：{}",
                    "The selected-profile record is not valid JSON: {}",
                    path.display()
                )
            })?;
        Ok(id.filter(|id| self.directory(*id).exists()))
    }
    pub fn select(&self, id: Option<Uuid>) -> Result<()> {
        if let Some(id) = id {
            self.get(id)?;
        }
        atomic_write(&self.root.join("selected.json"), &serde_json::to_vec(&id)?)
    }
    pub fn import_file(&self, path: &Path, password: Option<&str>) -> Result<ImportResult> {
        let source = String::from_utf8(read_limited(path, CONFIG_LIMIT)?)
            .with_context(|| tr!("配置不是 UTF-8 文本", "The profile is not UTF-8 text"))?;
        let yaml = match password {
            Some(password) => decrypt_source(&source, password)?,
            None => {
                ensure!(
                    !looks_encrypted(&source),
                    "{}",
                    tr!(
                        "配置已加密，需要密码",
                        "The profile is encrypted and needs a password"
                    )
                );
                source
            }
        };
        let (yaml, warnings) = crate::import::compatible_yaml(&yaml)?;
        let config = validate(&yaml)?;
        let source = path
            .parent()
            .with_context(|| tr!("无法读取配置目录", "Cannot read the profile directory"))?
            .canonicalize()?;
        let profile = self.create(
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            yaml,
            None,
            None,
        )?;
        let result = (|| {
            for name in resource_names(&config) {
                let relative = safe_relative(&name)?;
                let file = source.join(&relative);
                if !file.exists() {
                    continue;
                }
                let file = file.canonicalize()?;
                ensure!(
                    file.starts_with(&source),
                    "{}",
                    tr!(
                        "资源不能指向配置目录外部",
                        "Resources cannot point outside the profile directory"
                    )
                );
                atomic_write(
                    &self.runtime_dir(profile.id).join(relative),
                    &read_limited(&file, 128 * 1024 * 1024)?,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.delete(profile.id);
            return Err(error);
        }
        Ok(ImportResult {
            profile: profile.summary(),
            warnings,
        })
    }

    pub fn import_subscription(
        &self,
        name: String,
        source: &str,
        url: String,
        password: Option<String>,
    ) -> Result<ImportResult> {
        let yaml = subscription_yaml(source, password.as_deref())?;
        let (yaml, warnings) = crate::import::compatible_yaml(&yaml)?;
        let profile = self.create(name, yaml, Some(url), password)?;
        Ok(ImportResult {
            profile: profile.summary(),
            warnings,
        })
    }
}

/// Encrypted files are a single Base64 blob (optionally line-wrapped), which a
/// valid YAML configuration can never be: it always contains `key: value` pairs.
pub fn looks_encrypted(source: &str) -> bool {
    let text = source.trim();
    text.len() >= 16
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') || b.is_ascii_whitespace()
        })
}

/// CFB has no authentication tag, so a wrong password yields garbage rather
/// than an error; anything that is not a UTF-8 YAML mapping is reported as such.
pub fn decrypt_source(source: &str, password: &str) -> Result<String> {
    ensure!(
        !password.is_empty(),
        "{}",
        tr!("密码不能为空", "The password cannot be empty")
    );
    let compact: Vec<u8> = source
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let failed = || {
        anyhow::anyhow!(tr!(
            "解密失败，请检查密码",
            "Decryption failed; check the password"
        ))
    };
    let plaintext = clyntis_config::crypto::decrypt(&compact, password).map_err(|_| failed())?;
    let yaml = String::from_utf8(plaintext.to_vec()).map_err(|_| failed())?;
    ensure!(
        matches!(serde_yaml::from_str::<Value>(&yaml), Ok(Value::Mapping(_))),
        "{}",
        tr!(
            "解密失败，请检查密码",
            "Decryption failed; check the password"
        )
    );
    Ok(yaml)
}

pub fn encrypt_yaml(yaml: &str, password: &str) -> Result<String> {
    ensure!(
        !password.is_empty(),
        "{}",
        tr!("密码不能为空", "The password cannot be empty")
    );
    clyntis_config::crypto::encrypt(yaml.as_bytes(), password)
}

/// Decrypts a downloaded subscription when it has a password.
pub fn subscription_yaml(source: &str, password: Option<&str>) -> Result<String> {
    match password {
        Some(password) => decrypt_source(source, password),
        None => {
            ensure!(
                !looks_encrypted(source),
                "{}",
                tr!(
                    "订阅内容已加密，请删除后重新添加并填写密码",
                    "The subscription is encrypted; remove it and add it again with the password"
                )
            );
            Ok(source.to_owned())
        }
    }
}

pub fn resource_names(config: &Config) -> Vec<String> {
    let mut names = vec!["geoip.dat".into(), "geosite.dat".into()];
    names.extend(
        config
            .rule_providers
            .values()
            .filter(|p| !p.path.is_empty())
            .map(|p| p.path.clone()),
    );
    names.sort();
    names.dedup();
    names
}

pub fn safe_relative(path: &str) -> Result<PathBuf> {
    ensure!(
        path.len() <= 512 && !path.contains([':', '\\']),
        "{}",
        tr!(
            "资源路径必须使用可移植的相对路径",
            "Resource paths must be portable relative paths"
        )
    );
    let path = Path::new(path);
    ensure!(
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "{}",
        tr!(
            "资源必须使用配置目录内的相对路径",
            "Resources must use relative paths inside the profile directory"
        )
    );
    // The journals and application data may never be overwritten by a provider.
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::CurDir)
                || !part.as_os_str().to_string_lossy().starts_with('.')),
        "{}",
        tr!(
            "资源路径不能包含隐藏文件",
            "Resource paths cannot contain hidden files"
        )
    );
    let name = path
        .file_name()
        .with_context(|| {
            tr!(
                "资源路径必须包含文件名",
                "Resource paths must include a file name"
            )
        })?
        .to_string_lossy();
    ensure!(
        !name.starts_with("clyntis-")
            && !matches!(
                name.as_ref(),
                "profile.json" | "settings.json" | "selected.json"
            ),
        "{}",
        tr!(
            "资源路径与运行文件冲突",
            "The resource path conflicts with a runtime file"
        )
    );
    Ok(path.to_owned())
}

pub fn validate(yaml: &str) -> Result<Config> {
    ensure!(
        yaml.len() <= CONFIG_LIMIT,
        "{}",
        tr!("配置超过 24 MiB", "The profile exceeds 24 MiB")
    );
    let config = Config::parse(yaml.as_bytes())
        .with_context(|| tr!("配置校验失败", "Profile validation failed"))?;
    let unsupported: Vec<_> = config
        .proxies
        .iter()
        .filter(|p| {
            !matches!(
                p.kind,
                ProxyKind::Vless | ProxyKind::Hysteria2 | ProxyKind::Tailscale
            )
        })
        .map(|p| p.name.as_str())
        .collect();
    ensure!(
        unsupported.is_empty(),
        "{}",
        tr!(
            "当前支持 VLESS、Hysteria2 和 Tailscale，以下节点协议未实现：{}",
            "Only VLESS, Hysteria2 and Tailscale are supported; these node protocols are not implemented: {}",
            unsupported.join(if crate::i18n::english() { ", " } else { "、" })
        )
    );
    for provider in config.rule_providers.values() {
        if !provider.path.is_empty() {
            safe_relative(&provider.path)?;
        }
    }
    Ok(config)
}

/// Operate on the YAML document, never Serialize(Config): credentials are skip_serializing.
/// `custom` rules (see [`Store::custom_rules`]) go before the profile's rules;
/// those the profile cannot use are left out.
pub fn runtime_yaml(
    profile: &Profile,
    settings: &Settings,
    secret: &str,
    custom: &[String],
) -> Result<String> {
    validate(&profile.yaml)?;
    settings.validate()?;
    let yaml = clyntis_config::custom::apply(&profile.yaml, custom)?.yaml;
    let mut document: Value = serde_yaml::from_str(&yaml)?;
    let map = document
        .as_mapping_mut()
        .with_context(|| tr!("配置必须是 YAML 对象", "The profile must be a YAML mapping"))?;
    settings.overrides.apply_to(map)?;
    for (key, value) in [
        ("port", Value::from(0)),
        ("socks-port", Value::from(0)),
        ("mixed-port", Value::from(settings.mixed_port)),
        ("allow-lan", Value::from(settings.allow_lan)),
        (
            "bind-address",
            Value::from(if settings.allow_lan {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            }),
        ),
        ("external-controller", Value::from("127.0.0.1:0")),
        ("external-ui", Value::from("")),
        ("secret", Value::from(secret)),
        ("mode", Value::from(profile.mode.clone())),
    ] {
        map.insert(Value::from(key), value);
    }
    // Logging must never write to a path supplied by a downloaded configuration.
    nested(map, "log")?.insert(Value::from("log-path"), Value::from(""));
    nested(map, "profile")?.insert(Value::from("store-selected"), Value::from(true));
    let tun = nested(map, "tun")?;
    let enabled = settings.capture == crate::settings::Capture::Tun;
    tun.insert(Value::from("enable"), Value::from(enabled));
    tun.insert(Value::from("auto-dns"), Value::from(settings.auto_dns));
    tun.insert(Value::from("auto-route"), Value::from(enabled));
    if let Some(interface) = settings.tun_interface.as_ref().filter(|s| !s.is_empty()) {
        tun.insert(Value::from("interface"), Value::from(interface.clone()));
    } else {
        tun.remove(Value::from("interface"));
    }
    if enabled {
        nested(map, "dns")?.insert(Value::from("enable"), Value::from(true));
    }
    let yaml = serde_yaml::to_string(&document)?;
    validate(&yaml)?;
    Ok(yaml)
}
fn nested<'a>(map: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    map.entry(Value::from(key))
        .or_insert(Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .with_context(|| tr!("配置项必须是对象", "The setting must be a mapping"))
}

pub fn subscription_url(url: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url)
        .with_context(|| tr!("订阅 URL 无效", "Invalid subscription URL"))?;
    ensure!(
        url.scheme() == "https" && url.host_str().is_some(),
        "{}",
        tr!("订阅需要使用 HTTPS URL", "Subscriptions need an HTTPS URL")
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{}",
        tr!(
            "请将订阅令牌放在 URL 路径或查询参数中",
            "Put the subscription token in the URL path or query"
        )
    );
    Ok(url)
}

pub async fn download(url: &str, password: Option<&str>) -> Result<String> {
    let yaml = subscription_yaml(&download_source(url).await?, password)?;
    validate(&yaml)?;
    Ok(yaml)
}

pub async fn download_source(url: &str) -> Result<String> {
    let url = subscription_url(url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Clyntis-Desktop/0.1")
        .build()?;
    // Do not return reqwest errors verbatim: they contain private subscription URLs.
    let mut response = client.get(url).send().await.map_err(|_| {
        anyhow::anyhow!(tr!(
            "订阅下载失败，请检查网络和 URL",
            "The subscription download failed; check the network and URL"
        ))
    })?;
    ensure!(
        response.status().is_success(),
        "{}",
        tr!(
            "订阅服务器返回 HTTP {}",
            "The subscription server returned HTTP {}",
            response.status().as_u16()
        )
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= CONFIG_LIMIT as u64),
        "{}",
        tr!("订阅超过 24 MiB", "The subscription exceeds 24 MiB")
    );
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        anyhow::anyhow!(tr!(
            "订阅下载中断",
            "The subscription download was interrupted"
        ))
    })? {
        ensure!(
            data.len() + chunk.len() <= CONFIG_LIMIT,
            "{}",
            tr!("订阅超过 24 MiB", "The subscription exceeds 24 MiB")
        );
        data.extend_from_slice(&chunk);
    }
    let yaml = String::from_utf8(data)
        .with_context(|| tr!("订阅不是 UTF-8 YAML", "The subscription is not UTF-8 YAML"))?;
    Ok(yaml)
}

#[cfg(test)]
mod tests {
    use super::*;
    const YAML: &str = "mixed-port: 7890\nproxies:\n- name: test\n  type: vless\n  server: example.com\n  port: 443\n  uuid: 11111111-1111-4111-8111-111111111111\nrules:\n- MATCH,DIRECT\n";
    #[test]
    fn the_decryption_ca_stays_out_of_the_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        let mut settings = Settings::default();
        settings.overrides.mitm = Some(clyntis_config::overrides::MitmSettings {
            enable: true,
            hostnames: vec!["*.ads.test".into()],
            ..Default::default()
        });
        store.save_settings(&settings).unwrap();
        // No CA yet: nothing to fill in.
        let filled = store.with_mitm_authority(settings.clone()).unwrap();
        assert!(filled.overrides.mitm.unwrap().ca_key.is_empty());
        store.save_mitm_authority("CERT", "KEY").unwrap();
        let filled = store.with_mitm_authority(settings).unwrap();
        let mitm = filled.overrides.mitm.unwrap();
        assert_eq!(
            (mitm.ca_cert.as_str(), mitm.ca_key.as_str()),
            ("CERT", "KEY")
        );
        let saved = std::fs::read_to_string(dir.path().join("settings.json")).unwrap();
        assert!(!saved.contains("KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("mitm-ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }
    #[test]
    fn credentials_survive_runtime_overrides_and_disk_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        let profile = store
            .create("test".into(), YAML.into(), None, None)
            .unwrap();
        let saved = store.get(profile.id).unwrap();
        assert_eq!(saved.yaml, YAML);
        let yaml = runtime_yaml(&saved, &Settings::default(), "test-secret", &[]).unwrap();
        assert!(yaml.contains("11111111-1111-4111-8111-111111111111"));
        let config = validate(&yaml).unwrap();
        assert_eq!(config.secret, "test-secret");
        assert_eq!(config.external_controller.as_deref(), Some("127.0.0.1:0"));
        assert!(!config.tun.enable);
    }
    #[test]
    fn encrypted_export_imports_with_password_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("store")).unwrap();
        let encrypted = encrypt_yaml(YAML, "s3cret").unwrap();
        assert!(looks_encrypted(&encrypted));
        assert!(!looks_encrypted(YAML));
        // Exported files may be line-wrapped by other tools.
        let wrapped = encrypted
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let path = dir.path().join("exported.txt");
        fs::write(&path, wrapped + "\n").unwrap();
        let error = store.import_file(&path, None).err().unwrap();
        assert!(error.to_string().contains("需要密码"));
        let error = store.import_file(&path, Some("wrong")).err().unwrap();
        assert!(error.to_string().contains("解密失败"));
        let result = store.import_file(&path, Some("s3cret")).unwrap();
        let profile = store.get(result.profile.id).unwrap();
        assert!(
            profile
                .yaml
                .contains("11111111-1111-4111-8111-111111111111")
        );
        // A decrypted local file is stored as plaintext; no password is retained.
        assert!(profile.password.is_none());
    }
    #[test]
    fn encrypted_subscription_keeps_password_for_updates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        let source = encrypt_yaml(YAML, "sub-pass").unwrap();
        assert!(
            store
                .import_subscription("s".into(), &source, "https://example.com/s".into(), None)
                .is_err()
        );
        let result = store
            .import_subscription(
                "s".into(),
                &source,
                "https://example.com/s".into(),
                Some("sub-pass".into()),
            )
            .unwrap();
        assert!(result.profile.encrypted);
        let profile = store.get(result.profile.id).unwrap();
        assert_eq!(profile.password.as_deref(), Some("sub-pass"));
        assert!(subscription_yaml(&source, profile.password.as_deref()).is_ok());
    }
    #[test]
    fn custom_rules_persist_validate_and_lead_runtime_rules() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        assert!(store.custom_rules().unwrap().is_empty());
        assert!(store.save_custom_rules(&["MATCH,DIRECT".into()]).is_err());
        assert!(store.save_custom_rules(&["BAD,x,DIRECT".into()]).is_err());
        store
            .save_custom_rules(&[
                " DOMAIN,a.test,REJECT ".into(),
                "DOMAIN,b.test,Missing".into(),
            ])
            .unwrap();
        let rules = store.custom_rules().unwrap();
        assert_eq!(rules, ["DOMAIN,a.test,REJECT", "DOMAIN,b.test,Missing"]);
        let profile = store
            .create("test".into(), YAML.into(), None, None)
            .unwrap();
        let yaml = runtime_yaml(&profile, &Settings::default(), &"s".repeat(32), &rules).unwrap();
        let config = validate(&yaml).unwrap();
        assert_eq!(config.rules, ["DOMAIN,a.test,REJECT", "MATCH,DIRECT"]);
    }
    #[test]
    fn app_settings_override_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        let mut profile = store
            .create("test".into(), YAML.into(), None, None)
            .unwrap();
        profile.yaml = format!("log-level: debug\nipv6: false\n{YAML}");
        let mut settings = Settings::default();
        let follow = runtime_yaml(&profile, &settings, &"s".repeat(32), &[]).unwrap();
        assert_eq!(validate(&follow).unwrap().log.log_level, "debug");
        settings.overrides.log_level = Some("info".into());
        settings.overrides.ipv6 = Some(true);
        let config =
            validate(&runtime_yaml(&profile, &settings, &"s".repeat(32), &[]).unwrap()).unwrap();
        assert_eq!(config.log.log_level, "info");
        assert!(config.ipv6 && config.dns.ipv6);
        settings.overrides.adblock = Some(clyntis_config::adblock::Settings {
            enabled: true,
            presets: vec!["awavenue".into()],
            custom: vec![],
            allow: vec!["ok.test".into()],
            ..Default::default()
        });
        let config =
            validate(&runtime_yaml(&profile, &settings, &"s".repeat(32), &[]).unwrap()).unwrap();
        assert!(config.adblock.enable);
        assert_eq!(config.adblock.lists.len(), 1);
        assert_eq!(config.adblock.allow, ["ok.test"]);
        settings.overrides.log_level = Some("loud".into());
        assert!(settings.validate().is_err());
    }
    #[test]
    fn invalid_save_preserves_previous_profile() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().into()).unwrap();
        let mut profile = store
            .create("test".into(), YAML.into(), None, None)
            .unwrap();
        profile.yaml = "unknown: value".into();
        assert!(store.save(&profile).is_err());
        assert_eq!(store.get(profile.id).unwrap().yaml, YAML);
    }
    #[test]
    fn resource_paths_cannot_escape_or_overwrite_journals() {
        for path in [
            "../x",
            "/tmp/x",
            ".meta-profile.json",
            "clyntis-tun-state.json",
            "a/../b",
        ] {
            assert!(safe_relative(path).is_err(), "{path}");
        }
        assert!(safe_relative("rule_provider/example.yaml").is_ok());
    }
    #[test]
    fn unsupported_protocols_and_non_yaml_are_rejected() {
        assert!(validate(&YAML.replace("type: vless", "type: trojan")).is_err());
        assert!(validate("dmxlc3M6Ly9mb28=").is_err());
        assert!(subscription_url("http://example.com/sub").is_err());
    }
}
