//! A write-ahead journal records exactly the settings this application owns.
#[cfg(windows)]
use anyhow::Context;
use anyhow::{Result, ensure};
use clyntis_desktop_model::{atomic_write, read_limited};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, process::Command};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snapshot(pub BTreeMap<String, serde_json::Value>);
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    original: Snapshot,
    applied: Snapshot,
}
#[derive(Default, Serialize, Deserialize)]
struct Journal {
    port: Option<u16>,
    entries: BTreeMap<String, Entry>,
}
pub struct ProxyGuard {
    path: PathBuf,
    journal: Journal,
}
impl ProxyGuard {
    pub fn recover(path: PathBuf) -> Result<Self> {
        let journal = if path.exists() {
            serde_json::from_slice(&read_limited(&path, 1024 * 1024)?)?
        } else {
            Journal::default()
        };
        let mut guard = Self { path, journal };
        guard.restore()?;
        Ok(guard)
    }
    fn save(&self) -> Result<()> {
        atomic_write(&self.path, &serde_json::to_vec(&self.journal)?)
    }
    pub fn enable(&mut self, port: u16) -> Result<()> {
        ensure!(port >= 1024, "invalid system proxy port");
        self.journal.port = Some(port);
        self.refresh()
    }
    pub fn refresh(&mut self) -> Result<()> {
        let Some(port) = self.journal.port else {
            return Ok(());
        };
        for service in services()? {
            if self.journal.entries.contains_key(&service) {
                continue;
            }
            let original = snapshot(&service)?;
            let applied = desired(&original, port);
            self.journal.entries.insert(
                service.clone(),
                Entry {
                    original,
                    applied: applied.clone(),
                },
            );
            self.save()?; // durable intent before any system mutation
            apply(&service, &applied)?;
        }
        Ok(())
    }
    pub fn restore(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for (service, entry) in self.journal.entries.clone() {
            match snapshot(&service).and_then(|current| {
                let (merged, conflict) = restoration(&current, &entry);
                if merged != current {
                    apply(&service, &merged)?;
                }
                Ok(conflict)
            }) {
                Ok(conflict) => {
                    self.journal.entries.remove(&service);
                    if conflict {
                        errors.push(format!(
                            "{service} 的代理设置被其他程序修改，已保留外部修改"
                        ));
                    }
                }
                Err(error) => errors.push(format!("{service}: {error}")),
            }
        }
        self.journal.port = None;
        if self.journal.entries.is_empty() {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        } else {
            self.save()?;
        }
        ensure!(errors.is_empty(), "{}", errors.join("；"));
        Ok(())
    }
}
// A partial application is recoverable. Once another application changes any
// field, preserve its complete proxy tuple (server, port and enabled flags).
fn restoration(current: &Snapshot, entry: &Entry) -> (Snapshot, bool) {
    let conflict = entry.applied.0.iter().any(|(key, value)| {
        current.0.get(key) != Some(value) && current.0.get(key) != entry.original.0.get(key)
    });
    if conflict {
        return (current.clone(), true);
    }
    let mut restored = current.clone();
    for (key, value) in &entry.original.0 {
        restored.0.insert(key.clone(), value.clone());
    }
    (restored, false)
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(target_os = "macos")]
fn native(action: &str, service: Option<&str>, value: Option<&Snapshot>) -> Result<String> {
    use std::{io::Write, process::Stdio};
    let mut command = Command::new(crate::sibling("clyntis-service-manager")?);
    command
        .arg(action)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(service) = service {
        command.arg(service);
    }
    let mut child = command.spawn()?;
    if let Some(value) = value {
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing helper stdin"))?
            .write_all(&serde_json::to_vec(&value.0)?)?;
    }
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "系统代理操作失败：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
#[cfg(target_os = "macos")]
fn services() -> Result<Vec<String>> {
    Ok(serde_json::from_str(&native("proxy-list", None, None)?)?)
}
#[cfg(target_os = "macos")]
fn snapshot(service: &str) -> Result<Snapshot> {
    Ok(Snapshot(serde_json::from_str(&native(
        "proxy-read",
        Some(service),
        None,
    )?)?))
}
#[cfg(target_os = "macos")]
fn desired(original: &Snapshot, port: u16) -> Snapshot {
    let mut values = original.0.clone();
    for kind in ["HTTP", "HTTPS", "SOCKS"] {
        values.insert(format!("{kind}Enable"), 1.into());
        values.insert(format!("{kind}Proxy"), "127.0.0.1".into());
        values.insert(format!("{kind}Port"), port.into());
    }
    values.insert("ProxyAutoConfigEnable".into(), 0.into());
    values.insert("ProxyAutoDiscoveryEnable".into(), 0.into());
    Snapshot(values)
}
#[cfg(target_os = "macos")]
fn apply(service: &str, target: &Snapshot) -> Result<()> {
    native("proxy-write", Some(service), Some(target))?;
    Ok(())
}

#[cfg(windows)]
fn powershell(script: &str, input: Option<&str>) -> Result<String> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x08000000)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("missing stdin")?
            .write_all(input.as_bytes())?;
    }
    drop(child.stdin.take());
    let result = child.wait_with_output()?;
    ensure!(
        result.status.success(),
        "Windows 系统代理操作失败：{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?
        .trim()
        .trim_start_matches('\u{feff}')
        .into())
}
#[cfg(windows)]
fn services() -> Result<Vec<String>> {
    Ok(vec!["current-user".into()])
}
#[cfg(windows)]
fn snapshot(_: &str) -> Result<Snapshot> {
    let value = powershell(
        concat!(
            include_str!("../../packaging/windows/proxy-native.ps1"),
            include_str!("../../packaging/windows/proxy-read.ps1")
        ),
        None,
    )?;
    Ok(Snapshot(serde_json::from_str(&value)?))
}
#[cfg(windows)]
fn desired(original: &Snapshot, port: u16) -> Snapshot {
    let mut values = original.0.clone();
    values.insert(
        "ProxyEnable".into(),
        serde_json::json!({"kind":"DWord", "value":1}),
    );
    values.insert("ProxyServer".into(), serde_json::json!({"kind":"String", "value":format!("http=127.0.0.1:{port};https=127.0.0.1:{port};socks=127.0.0.1:{port}")}));
    values.insert("AutoConfigURL".into(), serde_json::Value::Null);
    // Connection flags are updated by the write adapter through WinINet.
    values.insert(
        "ConnectionFlags".into(),
        serde_json::json!({"kind":"DWord", "value":3}),
    );
    Snapshot(values)
}
#[cfg(windows)]
fn apply(_: &str, target: &Snapshot) -> Result<()> {
    powershell(
        concat!(
            include_str!("../../packaging/windows/proxy-native.ps1"),
            include_str!("../../packaging/windows/proxy-write.ps1")
        ),
        Some(&serde_json::to_string(&target.0)?),
    )?;
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn services() -> Result<Vec<String>> {
    anyhow::bail!("system proxy is supported on Windows and macOS only")
}
#[cfg(not(any(windows, target_os = "macos")))]
fn snapshot(_: &str) -> Result<Snapshot> {
    anyhow::bail!("unsupported platform")
}
#[cfg(not(any(windows, target_os = "macos")))]
fn desired(original: &Snapshot, _: u16) -> Snapshot {
    original.clone()
}
#[cfg(not(any(windows, target_os = "macos")))]
fn apply(_: &str, _: &Snapshot) -> Result<()> {
    anyhow::bail!("unsupported platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(value: serde_json::Value) -> Snapshot {
        Snapshot(serde_json::from_value(value).unwrap())
    }
    #[test]
    fn interrupted_application_restores_original_values() {
        let original = snapshot(serde_json::json!({"enabled":0,"server":null,"port":null}));
        let applied = snapshot(serde_json::json!({"enabled":1,"server":"127.0.0.1","port":7890}));
        let partial = snapshot(serde_json::json!({"enabled":0,"server":"127.0.0.1","port":null}));
        assert_eq!(
            restoration(
                &partial,
                &Entry {
                    original: original.clone(),
                    applied
                }
            ),
            (original, false)
        );
    }
    #[test]
    fn external_change_preserves_whole_proxy_tuple() {
        let original = snapshot(serde_json::json!({"enabled":0,"server":null,"port":null}));
        let applied = snapshot(serde_json::json!({"enabled":1,"server":"127.0.0.1","port":7890}));
        let external =
            snapshot(serde_json::json!({"enabled":1,"server":"other-proxy","port":7890}));
        assert_eq!(
            restoration(&external, &Entry { original, applied }),
            (external, true)
        );
    }
}
