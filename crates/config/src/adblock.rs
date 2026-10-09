//! Domain-level ad blocking: lists of ad, tracking and analytics domains that
//! DNS answers with NXDOMAIN and connections refuse, ahead of every rule. The
//! apps write the `adblock` section from their settings (see `overrides`).
use crate::rule::DomainSetBuilder;
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// The configuration section.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Adblock {
    pub enable: bool,
    pub lists: Vec<List>,
    /// Domains never blocked: a plain domain also covers its subdomains;
    /// `+.`, `.` and `*` patterns work as in rules.
    pub allow: Vec<String>,
    /// Seconds between list updates.
    pub interval: u64,
}
impl Default for Adblock {
    fn default() -> Self {
        Self {
            enable: false,
            lists: Vec::new(),
            allow: Vec::new(),
            interval: 86_400,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct List {
    pub name: String,
    pub url: String,
    /// `clash` (rule-provider yaml or text, domain behavior), `hosts` or
    /// `adguard` (`||domain^` rules; `@@` exceptions allow).
    #[serde(default = "clash")]
    pub format: String,
}
fn clash() -> String {
    "clash".into()
}

pub const FORMATS: [&str; 3] = ["clash", "hosts", "adguard"];

/// Lists the apps offer by default.
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub format: &'static str,
    pub description: &'static str,
}
pub const PRESETS: [Preset; 3] = [
    Preset {
        id: "awavenue",
        name: "AWAvenue-Ads",
        url: "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.yaml",
        format: "clash",
        description: "国内 App 广告接口，约 1,000 条，误杀少",
    },
    Preset {
        id: "anti-ad",
        name: "anti-AD",
        url: "https://anti-ad.net/clash.yaml",
        format: "clash",
        description: "覆盖面广，以国内为主，约 10 万条",
    },
    Preset {
        id: "adguard-dns",
        name: "AdGuard DNS filter",
        url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        format: "adguard",
        description: "偏海外的广告与追踪，约 18 万条，内存占用较大",
    },
];

impl Adblock {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.interval >= 3600,
            "adblock.interval must be at least 3600 seconds"
        );
        let mut names = std::collections::HashSet::new();
        for list in &self.lists {
            ensure!(
                !list.name.trim().is_empty()
                    && list.name.len() <= 64
                    && names.insert(list.file_name()),
                "adblock list names must be non-empty, unique and at most 64 bytes"
            );
            ensure!(
                list.url.starts_with("https://") || list.url.starts_with("http://"),
                "adblock list {}: url must be http(s)",
                list.name
            );
            ensure!(
                FORMATS.contains(&list.format.as_str()),
                "adblock list {}: format must be clash, hosts or adguard",
                list.name
            );
        }
        ensure!(
            self.allow.len() <= 10_000,
            "adblock.allow has too many entries"
        );
        let mut builder = DomainSetBuilder::default();
        for pattern in &self.allow {
            allow_pattern(&mut builder, pattern)?;
        }
        Ok(())
    }
}
impl List {
    /// The cache file, inside the configuration directory: never a path from
    /// the configuration.
    pub fn file_name(&self) -> String {
        let name: String = self
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("adblock/{name}.list")
    }
}

/// An allowlist entry: plain domains cover their subdomains.
pub fn allow_pattern(builder: &mut DomainSetBuilder, pattern: &str) -> Result<()> {
    let pattern = pattern.trim().trim_end_matches('.');
    ensure!(!pattern.is_empty(), "empty adblock allow entry");
    if pattern.starts_with("+.") || pattern.starts_with('.') || pattern.contains('*') {
        builder.pattern(pattern)
    } else {
        builder.suffix(pattern);
        Ok(())
    }
}

/// Feeds one downloaded list into the block and allow sets; returns the
/// number of entries taken. Lines a DNS filter cannot express (cosmetic,
/// URL-path, regex or modifier rules) are skipped.
pub fn parse_list(
    data: &[u8],
    format: &str,
    block: &mut DomainSetBuilder,
    allow: &mut DomainSetBuilder,
) -> Result<usize> {
    let text = String::from_utf8_lossy(data);
    let mut taken = 0;
    match format {
        "clash" => {
            for line in text.lines() {
                let line = line.trim();
                // yaml `payload:` items and plain text lines alike.
                let entry = line
                    .strip_prefix("- ")
                    .unwrap_or(line)
                    .trim()
                    .trim_matches(|c| c == '\'' || c == '"');
                if entry.is_empty() || entry.starts_with('#') || entry == "payload:" {
                    continue;
                }
                if let Some(rule) = entry.split_once(',') {
                    // A classical line: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD.
                    let value = rule.1.split(',').next().unwrap_or("").trim();
                    match rule.0.trim() {
                        "DOMAIN" => block.exact(value),
                        "DOMAIN-SUFFIX" => block.suffix(value),
                        "DOMAIN-KEYWORD" => block.keyword(value),
                        _ => continue,
                    }
                } else if block.pattern(entry).is_err() {
                    continue;
                }
                taken += 1;
            }
        }
        "hosts" => {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                let mut fields = line.split_whitespace();
                let (Some(address), Some(_)) = (fields.next(), fields.clone().next()) else {
                    continue;
                };
                if !matches!(address, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
                    continue;
                }
                for domain in fields {
                    if !matches!(
                        domain,
                        "localhost"
                            | "localhost.localdomain"
                            | "local"
                            | "broadcasthost"
                            | "0.0.0.0"
                    ) && domain.contains('.')
                    {
                        block.exact(domain);
                        taken += 1;
                    }
                }
            }
        }
        "adguard" => {
            for line in text.lines() {
                let line = line.trim();
                let (exception, rule) = match line.strip_prefix("@@") {
                    Some(rest) => (true, rest),
                    None => (false, line),
                };
                let Some(rule) = rule.strip_prefix("||") else {
                    continue;
                };
                // `$important` keeps its meaning at DNS level; other modifiers
                // (badfilter, client, dnstype…) cannot be honoured: skip.
                let (domain, modifiers) = rule.split_once('$').unwrap_or((rule, ""));
                if !modifiers.is_empty() && modifiers != "important" {
                    continue;
                }
                let Some(domain) = domain.strip_suffix('^') else {
                    continue;
                };
                if domain.is_empty()
                    || domain.ends_with('.')
                    || !domain
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'*')
                {
                    continue;
                }
                let target = if exception { &mut *allow } else { &mut *block };
                if domain.contains('*') {
                    if target.pattern(domain).is_err() {
                        continue;
                    }
                } else {
                    target.suffix(domain);
                }
                taken += 1;
            }
        }
        other => bail!("unsupported adblock list format {other}"),
    }
    Ok(taken)
}

/// What the apps store: which presets are on, extra lists and the allowlist.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    /// Preset ids (see [`PRESETS`]).
    pub presets: Vec<String>,
    pub custom: Vec<List>,
    pub allow: Vec<String>,
}
impl Settings {
    pub fn to_config(&self) -> Result<Adblock> {
        let mut lists = Vec::new();
        for id in &self.presets {
            let Some(preset) = PRESETS.iter().find(|p| p.id == id) else {
                bail!("unknown adblock list {id}");
            };
            lists.push(List {
                name: preset.name.into(),
                url: preset.url.into(),
                format: preset.format.into(),
            });
        }
        lists.extend(self.custom.iter().cloned());
        let adblock = Adblock {
            enable: self.enabled,
            lists,
            allow: self.allow.clone(),
            ..Adblock::default()
        };
        adblock.validate()?;
        Ok(adblock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &str, format: &str) -> (crate::rule::DomainSet, crate::rule::DomainSet, usize) {
        let (mut block, mut allow) = (DomainSetBuilder::default(), DomainSetBuilder::default());
        let taken = parse_list(data.as_bytes(), format, &mut block, &mut allow).unwrap();
        (block.build(), allow.build(), taken)
    }

    #[test]
    fn parses_clash_yaml_text_and_classical_lists() {
        let (block, _, taken) = parse(
            "#Title: x\npayload:\n  - 'ad.example.com'\n  - '+.tracker.test'\n  - \"*.wild.test\"\n",
            "clash",
        );
        assert_eq!(taken, 3);
        assert!(block.matches("ad.example.com") && !block.matches("x.ad.example.com"));
        assert!(block.matches("tracker.test") && block.matches("a.tracker.test"));
        assert!(block.matches("x.wild.test"));
        let (block, _, taken) = parse(
            "DOMAIN-SUFFIX,ads.test\nDOMAIN,one.test\nIP-CIDR,1.2.3.0/24\n",
            "clash",
        );
        assert_eq!(taken, 2);
        assert!(block.matches("x.ads.test") && block.matches("one.test"));
    }

    #[test]
    fn parses_hosts_and_adguard_with_exceptions() {
        let (block, _, taken) = parse(
            "# c\n0.0.0.0 ad.test b.test\n127.0.0.1 localhost\n10.0.0.1 lan.test\n",
            "hosts",
        );
        assert_eq!(taken, 2);
        assert!(block.matches("ad.test") && block.matches("b.test") && !block.matches("lan.test"));
        let rules = "! comment\n||ads.test^\n||imp.test^$important\n||bad.test^$badfilter\n@@||ok.ads.test^\n/^1\\.2/\n||partial.\n.cosmetic.test^\n";
        let (block, allow, taken) = parse(rules, "adguard");
        assert_eq!(taken, 3);
        assert!(
            block.matches("x.ads.test") && block.matches("imp.test") && !block.matches("bad.test")
        );
        assert!(allow.matches("ok.ads.test"));
    }

    #[test]
    fn settings_expand_presets_and_validate() {
        let settings = Settings {
            enabled: true,
            presets: vec!["awavenue".into()],
            custom: vec![List {
                name: "Mine".into(),
                url: "https://example.com/l.txt".into(),
                format: "hosts".into(),
            }],
            allow: vec!["wechat.com".into()],
        };
        let config = settings.to_config().unwrap();
        assert_eq!(config.lists.len(), 2);
        assert_eq!(config.lists[1].file_name(), "adblock/mine.list");
        let unknown = Settings {
            presets: vec!["nope".into()],
            ..Settings::default()
        };
        assert!(unknown.to_config().is_err());
        let bad = Settings {
            custom: vec![List {
                name: "x".into(),
                url: "ftp://x".into(),
                format: "clash".into(),
            }],
            ..Settings::default()
        };
        assert!(bad.to_config().is_err());
    }
}
