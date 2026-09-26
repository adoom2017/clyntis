use crate::Core;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
#[derive(Default, Serialize, Deserialize)]
struct Saved {
    #[serde(default)]
    selection: std::collections::HashMap<String, String>,
    #[serde(default)]
    fake: Vec<(String, std::net::IpAddr)>,
}
impl Core {
    pub(crate) fn load_profile(&self) -> Result<()> {
        if !self.config.profile.store_selected && !self.config.profile.store_fake_ip {
            return Ok(());
        }
        let path = self.config.directory.join(".meta-profile.json");
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        ensure!(metadata.len() <= 8 * 1024 * 1024, "profile too large");
        let saved: Saved = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("invalid saved profile at {}", path.display()))?;
        if self.config.profile.store_fake_ip {
            self.resolver.import_fake(&saved.fake)
                .with_context(|| format!("cannot restore fake-IP mappings from {}", path.display()))?;
        }
        if self.config.profile.store_selected {
            let mut policy = self.policy.write().unwrap();
            for (group, node) in saved.selection {
                if self
                    .config
                    .proxy_groups
                    .iter()
                    .any(|g| g.name == group && g.proxies.contains(&node))
                {
                    policy.selection.insert(group, node);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn save_profile(&self) -> Result<()> {
        if !self.config.profile.store_selected && !self.config.profile.store_fake_ip {
            return Ok(());
        }
        let saved = Saved {
            selection: if self.config.profile.store_selected {
                self.policy.read().unwrap().selection.clone()
            } else {
                Default::default()
            },
            fake: if self.config.profile.store_fake_ip {
                self.resolver.export_fake()
            } else {
                vec![]
            },
        };
        crate::resources::atomic_write(
            &self.config.directory.join(".meta-profile.json"),
            &serde_json::to_vec(&saved)?,
        )
    }
}
