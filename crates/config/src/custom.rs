//! Rules the user adds outside any profile. They are matched before the
//! profile's own rules, so they take priority over it on every platform.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_yaml::Value;
use std::collections::HashSet;

/// At most this many custom rules; each is a single rule line.
pub const MAX_RULES: usize = 1000;

/// A custom rule left out of a profile because it cannot apply there.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Skipped {
    pub rule: String,
    pub reason: String,
}

/// Profile YAML with the applicable custom rules first.
#[derive(Clone, Debug)]
pub struct Applied {
    pub yaml: String,
    pub skipped: Vec<Skipped>,
}

/// Checks the syntax of one custom rule (`TYPE,VALUE,TARGET[,no-resolve]`).
/// Whether the target exists depends on the profile and is checked by `apply`.
pub fn validate(rule: &str) -> Result<()> {
    ensure!(
        !rule.trim().is_empty() && rule.len() <= 4096,
        "规则不能为空且不能超过 4096 字节"
    );
    ensure!(!rule.contains(['\n', '\r']), "一条规则只能占一行");
    let parsed = crate::rule::Rule::parse(rule.trim())?;
    if matches!(parsed.matcher, crate::rule::Matcher::All) {
        bail!("MATCH 会覆盖配置中的全部规则，不能作为自定义规则");
    }
    Ok(())
}

/// Rule targets a profile offers, in display order: DIRECT, REJECT, then its
/// proxy groups and proxies.
pub fn targets(yaml: &str) -> Result<Vec<String>> {
    let document: Value = serde_yaml::from_str(yaml).context("配置不是有效的 YAML")?;
    let map = document.as_mapping().context("配置必须是 YAML 对象")?;
    let mut names = vec!["DIRECT".to_owned(), "REJECT".to_owned()];
    for key in ["proxy-groups", "proxies"] {
        for item in map
            .get(key)
            .and_then(Value::as_sequence)
            .into_iter()
            .flatten()
        {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && !names.iter().any(|n| n == name)
            {
                names.push(name.to_owned());
            }
        }
    }
    Ok(names)
}

/// Prepends the custom rules that can apply to this profile. A rule whose
/// target or rule provider the profile lacks is skipped with a reason, so a
/// rule written for one profile never prevents another from starting.
pub fn apply(yaml: &str, rules: &[String]) -> Result<Applied> {
    ensure!(
        rules.len() <= MAX_RULES,
        "自定义规则不能超过 {MAX_RULES} 条"
    );
    let mut document: Value = serde_yaml::from_str(yaml).context("配置不是有效的 YAML")?;
    let names: HashSet<String> = targets(yaml)?
        .into_iter()
        .chain(["GLOBAL".into()])
        .collect();
    let map = document.as_mapping_mut().context("配置必须是 YAML 对象")?;
    let providers: HashSet<String> = map
        .get("rule-providers")
        .and_then(Value::as_mapping)
        .map(|providers| {
            providers
                .keys()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    for raw in rules {
        let rule = raw.trim();
        let skip = |reason: String| Skipped {
            rule: rule.to_owned(),
            reason,
        };
        if let Err(error) = validate(rule) {
            skipped.push(skip(format!("{error:#}")));
            continue;
        }
        let parsed = crate::rule::Rule::parse(rule)?;
        if !names.contains(&parsed.target) {
            skipped.push(skip(format!(
                "当前配置没有代理或代理组「{}」",
                parsed.target
            )));
            continue;
        }
        let mut refs = vec![];
        parsed.matcher.references(&mut refs);
        if let Some((_, name)) = refs
            .iter()
            .find(|(kind, name)| kind == "rule-set" && !providers.contains(name))
        {
            skipped.push(skip(format!("当前配置没有规则集「{name}」")));
            continue;
        }
        kept.push(Value::from(rule));
    }
    if !kept.is_empty() {
        let existing = map
            .remove(Value::from("rules"))
            .and_then(|v| match v {
                Value::Sequence(items) => Some(items),
                _ => None,
            })
            .unwrap_or_default();
        kept.extend(existing);
        map.insert(Value::from("rules"), Value::Sequence(kept));
    }
    Ok(Applied {
        yaml: serde_yaml::to_string(&document)?,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "proxies:\n  - {name: node, type: vless, server: example.com, port: 443, uuid: 11111111-1111-4111-8111-111111111111, network: tcp}\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [node, DIRECT]}\nrule-providers:\n  ads: {type: inline, behavior: domain, payload: ['+.ads.test']}\nrules:\n  - DOMAIN-SUFFIX,example.com,DIRECT\n  - MATCH,Proxy\n";

    #[test]
    fn validates_syntax_and_refuses_match() {
        assert!(validate("DOMAIN-SUFFIX,example.com,Proxy").is_ok());
        assert!(validate("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").is_ok());
        assert!(validate("MATCH,DIRECT").is_err());
        assert!(validate("NOT-A-RULE,x,DIRECT").is_err());
        assert!(validate("DOMAIN,a.test,DIRECT\nMATCH,REJECT").is_err());
        assert!(validate("  ").is_err());
    }

    #[test]
    fn lists_targets_in_display_order() {
        assert_eq!(
            targets(PROFILE).unwrap(),
            ["DIRECT", "REJECT", "Proxy", "node"]
        );
    }

    #[test]
    fn prepends_applicable_rules_and_skips_the_rest() {
        let rules = [
            "DOMAIN,example.com,REJECT".to_owned(),
            "DOMAIN-SUFFIX,video.test,Missing".to_owned(),
            "RULE-SET,ads,REJECT".to_owned(),
            "RULE-SET,absent,REJECT".to_owned(),
            "MATCH,DIRECT".to_owned(),
        ];
        let applied = apply(PROFILE, &rules).unwrap();
        let config = crate::Config::parse(applied.yaml.as_bytes()).unwrap();
        assert_eq!(
            config.rules,
            [
                "DOMAIN,example.com,REJECT",
                "RULE-SET,ads,REJECT",
                "DOMAIN-SUFFIX,example.com,DIRECT",
                "MATCH,Proxy"
            ]
        );
        let reasons: Vec<_> = applied.skipped.iter().map(|s| s.rule.as_str()).collect();
        assert_eq!(
            reasons,
            [
                "DOMAIN-SUFFIX,video.test,Missing",
                "RULE-SET,absent,REJECT",
                "MATCH,DIRECT"
            ]
        );
        // Credentials survive the YAML round trip.
        assert!(
            applied
                .yaml
                .contains("11111111-1111-4111-8111-111111111111")
        );
        // No custom rules: the profile is unchanged in meaning.
        let untouched = apply(PROFILE, &[]).unwrap();
        assert_eq!(
            crate::Config::parse(untouched.yaml.as_bytes())
                .unwrap()
                .rules
                .len(),
            2
        );
    }
}
