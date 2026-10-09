//! Settings the user picks in the app. Each one replaces the profile's own
//! value on every platform; `None` keeps whatever the profile says.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

pub const LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "silent"];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Overrides {
    /// debug, info, warning, error or silent.
    pub log_level: Option<String>,
    /// Top-level `ipv6` and `dns.ipv6` together, so AAAA answers and IPv6
    /// routing agree.
    pub ipv6: Option<bool>,
    /// `sniffer.enable`. Turning it on for a profile without sniff rules adds
    /// mihomo's usual HTTP and TLS ports.
    pub sniffing: Option<bool>,
    /// Ad blocking from the app's settings; replaces the profile's `adblock`.
    pub adblock: Option<crate::adblock::Settings>,
}

impl Overrides {
    pub fn validate(&self) -> Result<()> {
        if let Some(level) = &self.log_level {
            ensure!(
                LOG_LEVELS.contains(&level.as_str()),
                "无效日志级别「{level}」"
            );
        }
        if let Some(adblock) = &self.adblock {
            adblock.to_config()?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Writes the chosen values into a parsed profile.
    pub fn apply_to(&self, map: &mut Mapping) -> Result<()> {
        self.validate()?;
        if let Some(adblock) = &self.adblock {
            map.insert(
                Value::from("adblock"),
                serde_yaml::to_value(adblock.to_config()?)?,
            );
        }
        if let Some(level) = &self.log_level {
            // The top-level key wins over `log.log-level` when both exist.
            map.insert(Value::from("log-level"), Value::from(level.as_str()));
        }
        if let Some(ipv6) = self.ipv6 {
            map.insert(Value::from("ipv6"), Value::from(ipv6));
            nested(map, "dns")?.insert(Value::from("ipv6"), Value::from(ipv6));
        }
        if let Some(sniffing) = self.sniffing {
            let sniffer = nested(map, "sniffer")?;
            sniffer.insert(Value::from("enable"), Value::from(sniffing));
            let empty = sniffer
                .get("sniff")
                .and_then(Value::as_mapping)
                .is_none_or(Mapping::is_empty);
            if sniffing && empty {
                sniffer.insert(
                    Value::from("sniff"),
                    serde_yaml::from_str(
                        "HTTP: {ports: [80, 8080-8880], override-destination: true}\n\
                         TLS: {ports: [443, 8443]}\n",
                    )?,
                );
            }
        }
        Ok(())
    }

    /// The profile YAML with the chosen values applied.
    pub fn apply(&self, yaml: &str) -> Result<String> {
        if self.is_empty() {
            return Ok(yaml.to_owned());
        }
        let mut document: Value = serde_yaml::from_str(yaml).context("配置不是有效的 YAML")?;
        self.apply_to(document.as_mapping_mut().context("配置必须是 YAML 对象")?)?;
        Ok(serde_yaml::to_string(&document)?)
    }
}

fn nested<'a>(map: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    map.entry(Value::from(key))
        .or_insert(Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .with_context(|| format!("配置项 {key} 必须是对象"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "log-level: debug\nipv6: false\ndns:\n  enable: true\n  ipv6: false\nsniffer:\n  enable: false\n  sniff:\n    TLS: {ports: [443]}\n";

    #[test]
    fn unset_values_keep_the_profile() {
        assert_eq!(Overrides::default().apply(PROFILE).unwrap(), PROFILE);
        let config = crate::Config::parse(PROFILE.as_bytes()).unwrap();
        assert_eq!(config.log.log_level, "debug");
    }

    #[test]
    fn chosen_values_replace_the_profile() {
        let overrides = Overrides {
            log_level: Some("warning".into()),
            ipv6: Some(true),
            sniffing: Some(true),
            adblock: Some(crate::adblock::Settings {
                enabled: true,
                presets: vec!["awavenue".into()],
                custom: vec![],
                allow: vec!["ok.test".into()],
            }),
        };
        let config = crate::Config::parse(overrides.apply(PROFILE).unwrap().as_bytes()).unwrap();
        assert_eq!(config.log.log_level, "warning");
        assert!(config.ipv6 && config.dns.ipv6);
        assert!(config.sniffer.enable);
        assert!(config.adblock.enable);
        assert_eq!(config.adblock.lists[0].name, "AWAvenue-Ads");
        assert_eq!(config.adblock.allow, ["ok.test"]);
        // The profile's own sniff rules are kept.
        assert_eq!(config.sniffer.sniff.keys().collect::<Vec<_>>(), ["TLS"]);
        // Nested `log.log-level` cannot win over the chosen level.
        let nested = "log:\n  log-level: debug\n";
        let config = crate::Config::parse(overrides.apply(nested).unwrap().as_bytes()).unwrap();
        assert_eq!(config.log.log_level, "warning");
    }

    #[test]
    fn sniffing_without_rules_gets_default_ports() {
        let overrides = Overrides {
            sniffing: Some(true),
            ..Overrides::default()
        };
        let config =
            crate::Config::parse(overrides.apply("mode: rule\n").unwrap().as_bytes()).unwrap();
        assert!(config.sniffer.enable);
        assert_eq!(
            config.sniffer.sniff.keys().collect::<Vec<_>>(),
            ["HTTP", "TLS"]
        );
    }

    #[test]
    fn rejects_unknown_log_levels() {
        let overrides = Overrides {
            log_level: Some("verbose".into()),
            ..Overrides::default()
        };
        assert!(overrides.apply(PROFILE).is_err());
        assert!(serde_json::from_str::<Overrides>(r#"{"logLevel":"info","extra":1}"#).is_err());
    }
}
