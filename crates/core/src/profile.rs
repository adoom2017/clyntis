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
            self.resolver.import_fake(&saved.fake).with_context(|| {
                format!("cannot restore fake-IP mappings from {}", path.display())
            })?;
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
    fn profile_needs_save(&self) -> bool {
        if !self.config.profile.store_selected && !self.config.profile.store_fake_ip {
            return false;
        }
        let generation = if self.config.profile.store_fake_ip {
            self.resolver.fake_generation()
        } else {
            0
        };
        let Ok(last) = self.saved_profile.try_lock() else {
            return true;
        };
        let Some((saved, saved_generation)) = last.as_ref() else {
            return true;
        };
        if *saved_generation != generation {
            return true;
        }
        if self.config.profile.store_selected {
            let policy = self.policy.read().unwrap();
            if *saved != policy.selection {
                return true;
            }
        }
        false
    }
    pub(crate) async fn save_profile_async(self: &std::sync::Arc<Self>) -> Result<()> {
        if !self.profile_needs_save() {
            return Ok(());
        }
        let core = std::sync::Arc::clone(self);
        tokio::task::spawn_blocking(move || core.save_profile())
            .await
            .context("profile save task failed")?
    }
    pub(crate) fn save_profile(&self) -> Result<()> {
        if !self.config.profile.store_selected && !self.config.profile.store_fake_ip {
            return Ok(());
        }
        let selection = if self.config.profile.store_selected {
            self.policy.read().unwrap().selection.clone()
        } else {
            Default::default()
        };
        let generation = if self.config.profile.store_fake_ip {
            self.resolver.fake_generation()
        } else {
            0
        };
        // Called every few seconds: export and write only after a change.
        let mut last = self.saved_profile.lock().unwrap();
        if last.as_ref().is_some_and(|(saved, saved_generation)| {
            *saved == selection && *saved_generation == generation
        }) {
            return Ok(());
        }
        let saved = Saved {
            selection,
            fake: if self.config.profile.store_fake_ip {
                self.resolver.export_fake()
            } else {
                vec![]
            },
        };
        crate::resources::atomic_write(
            &self.config.directory.join(".meta-profile.json"),
            &serde_json::to_vec(&saved)?,
        )?;
        *last = Some((saved.selection, generation));
        Ok(())
    }
}
