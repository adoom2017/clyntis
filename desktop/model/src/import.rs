//! Lossy import is explicit and confined to newly created profiles. Keep raw YAML
//! values: serializing Config would discard credentials and provider URLs.
use anyhow::{Context, Result, ensure};
use meta_config::{Config, Group, Proxy, ProxyKind, RuleProvider};
use serde::{Serialize, de::DeserializeOwned};
use serde_yaml::{Mapping, Value};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize)]
pub struct ImportWarning {
    pub path: String,
    pub reason: String,
}

fn warn(warnings: &mut Vec<ImportWarning>, path: impl Into<String>, reason: &str) {
    warnings.push(ImportWarning {
        path: crate::redact(path.into().trim_start_matches('.')),
        reason: reason.into(),
    });
}

// Only remove unknown fields here. Invalid transports/credentials cause the
// whole node to be skipped, rather than silently changing its protocol.
fn known_fields<T: DeserializeOwned>(
    value: &mut Value,
    path: &str,
    warnings: &mut Vec<ImportWarning>,
) -> Result<T> {
    loop {
        match serde_path_to_error::deserialize::<_, T>(value.clone()) {
            Ok(parsed) => return Ok(parsed),
            Err(error) => {
                let message = error.inner().to_string();
                let Some(key) = message
                    .strip_prefix("unknown field `")
                    .and_then(|s| s.split('`').next())
                else {
                    return Err(error.into());
                };
                let mut parent = &mut *value;
                let mut location = path.to_owned();
                let segments: Vec<_> = error.path().iter().collect();
                for (index, segment) in segments.iter().enumerate() {
                    // serde includes the rejected key itself in the error path.
                    if index + 1 == segments.len()
                        && matches!(segment, serde_path_to_error::Segment::Map { key: field } if field == key)
                    {
                        break;
                    }
                    match segment {
                        serde_path_to_error::Segment::Map { key } => {
                            location.push_str(&format!(".{key}"));
                            parent = parent.get_mut(key).context("missing field")?;
                        }
                        serde_path_to_error::Segment::Seq { index } => {
                            location.push_str(&format!("[{index}]"));
                            parent = parent.get_mut(*index).context("missing item")?;
                        }
                        _ => anyhow::bail!("unsupported field path"),
                    }
                }
                ensure!(
                    parent
                        .as_mapping_mut()
                        .and_then(|m| m.remove(Value::from(key)))
                        .is_some(),
                    "missing unknown field"
                );
                warn(
                    warnings,
                    format!("{location}.{key}"),
                    "不支持的字段，已跳过",
                );
            }
        }
    }
}

fn valid(value: &Value) -> bool {
    serde_yaml::to_string(value).is_ok_and(|yaml| crate::profiles::validate(&yaml).is_ok())
}

// Try complete subtrees first so mutually dependent options remain together.
// On failure, salvage individual fields/list entries against the real validator.
fn settings(
    value: &Value,
    accepted: &mut Value,
    path: &mut Vec<Value>,
    warnings: &mut Vec<ImportWarning>,
) {
    let mut trial = accepted.clone();
    let mut slot = &mut trial;
    for key in path.iter() {
        slot = &mut slot[key.clone()];
    }
    *slot = value.clone();
    if valid(&trial) {
        *accepted = trial;
        return;
    }
    match value {
        Value::Mapping(map) if !map.is_empty() => {
            let mut deferred = vec![];
            for (key, child) in map {
                path.push(key.clone());
                let mut trial = accepted.clone();
                let mut slot = &mut trial;
                for key in path.iter() {
                    slot = &mut slot[key.clone()];
                }
                *slot = child.clone();
                if valid(&trial) {
                    *accepted = trial;
                } else {
                    deferred.push((key, child));
                }
                path.pop();
            }
            // Retry after sibling settings (e.g. controller secret) are present.
            for (key, child) in deferred {
                path.push(key.clone());
                settings(child, accepted, path, warnings);
                path.pop();
            }
        }
        Value::Sequence(items) if !items.is_empty() => {
            let mut kept = vec![];
            let location = path
                .iter()
                .map(|k| k.as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(".");
            for (i, item) in items.iter().enumerate() {
                let mut trial = accepted.clone();
                let mut slot = &mut trial;
                for key in path.iter() {
                    slot = &mut slot[key.clone()];
                }
                let mut candidate = kept.clone();
                candidate.push(item.clone());
                *slot = Value::Sequence(candidate.clone());
                if valid(&trial) {
                    *accepted = trial;
                    kept = candidate;
                } else {
                    warn(
                        warnings,
                        format!("{location}[{i}]"),
                        "不兼容的列表项，已跳过",
                    );
                }
            }
        }
        _ => warn(
            warnings,
            path.iter()
                .map(|k| k.as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join("."),
            "不兼容的配置项，已跳过并使用默认值",
        ),
    }
}

pub fn compatible_yaml(yaml: &str) -> Result<(String, Vec<ImportWarning>)> {
    ensure!(yaml.len() <= crate::CONFIG_LIMIT, "配置超过 24 MiB");
    let document: Value = serde_yaml::from_str(yaml).context("配置不是有效的 YAML")?;
    let mut source = document
        .as_mapping()
        .context("配置必须是 YAML 对象")?
        .clone();
    if crate::profiles::validate(yaml).is_ok() {
        return Ok((yaml.into(), vec![]));
    }
    let mut warnings = vec![];
    let proxies = source.remove("proxies");
    let groups = source.remove("proxy-groups");
    let rules = source.remove("rules");
    let providers = source.remove("rule-providers");
    let mut source = Value::Mapping(source);
    // Strip unknown fields before semantic checks, preserving dependent settings
    // such as an external controller and its secret as one complete subtree.
    let _ = known_fields::<Config>(&mut source, "", &mut warnings);
    let mut output = Value::Mapping(Mapping::new());
    settings(&source, &mut output, &mut vec![], &mut warnings);
    let mut config = Config::parse(serde_yaml::to_string(&output)?.as_bytes())?;
    let base = config.clone();
    let mut names: HashSet<String> = ["DIRECT", "REJECT", "GLOBAL"].map(String::from).into();
    let mut kept = vec![];
    for (i, mut value) in sequence(proxies, "proxies", &mut warnings)
        .into_iter()
        .enumerate()
    {
        let path = format!("proxies[{i}]");
        let parsed = known_fields::<Proxy>(&mut value, &path, &mut warnings);
        let Ok(proxy) = parsed else {
            warn(&mut warnings, path, "不支持的协议或无效节点，已跳过");
            continue;
        };
        let mut trial = base.clone();
        trial.proxies = vec![proxy.clone()];
        if proxy.kind != ProxyKind::Vless
            || trial.validate().is_err()
            || !names.insert(proxy.name.clone())
        {
            warn(
                &mut warnings,
                path,
                "仅支持有效且名称唯一的 VLESS 节点，已跳过",
            );
            continue;
        }
        kept.push(value);
        config.proxies.push(proxy);
    }
    output["proxies"] = Value::Sequence(kept);
    let mut group_values = vec![];
    let mut parsed_groups = vec![];
    for (i, mut value) in sequence(groups, "proxy-groups", &mut warnings)
        .into_iter()
        .enumerate()
    {
        let path = format!("proxy-groups[{i}]");
        let Ok(group) = known_fields::<Group>(&mut value, &path, &mut warnings) else {
            warn(&mut warnings, path, "不支持的代理组，已跳过");
            continue;
        };
        if group.name.is_empty() || group.interval == 0 || !names.insert(group.name.clone()) {
            warn(&mut warnings, path, "无效或重名的代理组，已跳过");
            continue;
        }
        parsed_groups.push(group);
        group_values.push((i, value));
    }
    // Remove cyclic edges and then cascade empty groups/missing references.
    let graph: HashMap<_, _> = parsed_groups
        .iter()
        .map(|g| (g.name.clone(), g.proxies.clone()))
        .collect();
    loop {
        let mut changed = false;
        for (group, (index, value)) in parsed_groups.iter_mut().zip(&mut group_values) {
            group.proxies.retain(|target| {
                let keep = target != "GLOBAL"
                    && names.contains(target)
                    && !reaches(target, &group.name, &graph);
                if !keep {
                    warn(
                        &mut warnings,
                        format!("proxy-groups[{index}].proxies"),
                        "已跳过不存在或形成循环的节点引用",
                    );
                    changed = true;
                }
                keep
            });
            value["proxies"] = serde_yaml::to_value(&group.proxies)?;
            if group.proxies.is_empty() && names.remove(&group.name) {
                warn(
                    &mut warnings,
                    format!("proxy-groups[{index}]"),
                    "代理组无兼容成员，已跳过",
                );
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    output["proxy-groups"] = Value::Sequence(
        group_values
            .into_iter()
            .zip(parsed_groups)
            .filter_map(|((_, value), group)| {
                if group.proxies.is_empty() {
                    None
                } else {
                    config.proxy_groups.push(group);
                    Some(value)
                }
            })
            .collect(),
    );
    let mut kept = Mapping::new();
    if let Some(value) = providers {
        if let Value::Mapping(map) = value {
            for (key, mut value) in map {
                let path = format!("rule-providers.{}", key.as_str().unwrap_or("?"));
                let Ok(provider) = known_fields::<RuleProvider>(&mut value, &path, &mut warnings)
                else {
                    warn(&mut warnings, path, "不兼容的规则集，已跳过");
                    continue;
                };
                let mut trial = Config::default();
                trial.rule_providers.insert("test".into(), provider.clone());
                if key.as_str().is_none()
                    || trial.validate().is_err()
                    || (!provider.path.is_empty()
                        && crate::profiles::safe_relative(&provider.path).is_err())
                {
                    warn(&mut warnings, path, "不兼容的规则集或资源路径，已跳过");
                    continue;
                }
                config
                    .rule_providers
                    .insert(key.as_str().unwrap().into(), provider);
                kept.insert(key, value);
            }
        } else {
            warn(&mut warnings, "rule-providers", "规则集必须是对象，已跳过");
        }
    }
    output["rule-providers"] = Value::Mapping(kept);
    if rules.is_some() {
        let mut kept = vec![];
        for (i, value) in sequence(rules, "rules", &mut warnings)
            .into_iter()
            .enumerate()
        {
            let compatible = value.as_str().is_some_and(|raw| {
                meta_config::rule::Rule::parse(raw).is_ok_and(|rule| {
                    let mut references = vec![];
                    rule.matcher.references(&mut references);
                    names.contains(&rule.target)
                        && references.iter().all(|(kind, name)| {
                            kind != "rule-set" || config.rule_providers.contains_key(name)
                        })
                })
            });
            if compatible {
                kept.push(value);
            } else {
                warn(
                    &mut warnings,
                    format!("rules[{i}]"),
                    "不支持的规则或引用的节点、规则集不可用，已跳过",
                );
            }
        }
        output["rules"] = Value::Sequence(kept);
    }
    let yaml = serde_yaml::to_string(&output)?;
    crate::profiles::validate(&yaml).context("无法生成兼容配置")?;
    Ok((yaml, warnings))
}

fn sequence(value: Option<Value>, path: &str, warnings: &mut Vec<ImportWarning>) -> Vec<Value> {
    match value {
        Some(Value::Sequence(items)) => items,
        None => vec![],
        _ => {
            warn(warnings, path, "必须是列表，已跳过");
            vec![]
        }
    }
}

fn reaches(start: &str, target: &str, graph: &HashMap<String, Vec<String>>) -> bool {
    let mut pending = vec![start];
    let mut visited = HashSet::new();
    while let Some(name) = pending.pop() {
        if name == target {
            return true;
        }
        if visited.insert(name)
            && let Some(children) = graph.get(name)
        {
            pending.extend(children.iter().map(String::as_str));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    const MIXED: &str = r#"
mixed-port: 7890
unknown-option: true
secret: keep-secret
dns:
  enable: true
  fallback: [1.0.0.1]
  nameserver: [https://1.1.1.1/dns-query, quic://dns.example]
proxies:
  - {name: good, type: vless, server: example.com, port: 443, uuid: keep-uuid, tls: true, extra-option: true}
  - {name: ss, type: ss, server: example.com, port: 443, password: private}
  - {name: trojan, type: trojan, server: example.com, port: 443, password: private}
  - {name: bad, type: vless, server: example.com, port: 443, uuid: keep-uuid, network: unsupported}
proxy-groups:
  - {name: outer, type: select, proxies: [empty, good], extra: true}
  - {name: empty, type: select, proxies: [ss]}
  - {name: cycle1, type: select, proxies: [cycle2]}
  - {name: cycle2, type: select, proxies: [cycle1]}
  - {name: fallback, type: fallback, proxies: [good]}
rule-providers:
  valid: {type: http, behavior: domain, path: rules/test.yaml, url: 'https://example.com/rules?token=keep'}
  invalid: {type: http, behavior: domain, path: ../escape, url: 'https://example.com/rules'}
rules:
  - DOMAIN,example.com,outer
  - DOMAIN,example.org,empty
  - RULE-SET,valid,good
  - RULE-SET,invalid,good
  - UNKNOWN,example.com,DIRECT
  - MATCH,DIRECT
"#;

    #[test]
    fn mixed_import_preserves_credentials_and_cleans_dependencies() {
        let (yaml, warnings) = compatible_yaml(MIXED).unwrap();
        let config = crate::profiles::validate(&yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].name, "good");
        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].proxies, ["good"]);
        assert_eq!(config.rules.len(), 3);
        assert!(config.dns.enable);
        assert_eq!(config.dns.nameserver, ["https://1.1.1.1/dns-query"]);
        for credential in ["keep-uuid", "keep-secret", "token=keep"] {
            assert!(yaml.contains(credential));
        }
        for path in [
            "unknown-option",
            "dns.fallback",
            "proxies[0].extra-option",
            "proxy-groups[0].extra",
            "rule-providers.invalid",
            "rules[1]",
        ] {
            assert!(
                warnings.iter().any(|w| w.path == path),
                "missing {path}: {warnings:?}"
            );
        }
        let report = serde_json::to_string(&warnings).unwrap();
        assert!(!report.contains("private"));
        assert!(!report.contains("keep-secret"));
    }

    #[test]
    fn import_creates_new_profiles_without_touching_source_or_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.yaml");
        std::fs::write(&path, MIXED).unwrap();
        let store = crate::profiles::Store::new(dir.path().join("store")).unwrap();
        let first = store.import_file(&path).unwrap();
        store.select(Some(first.profile.id)).unwrap();
        let before = std::fs::read(store.directory(first.profile.id).join("profile.json")).unwrap();
        let second = store.import_file(&path).unwrap();
        assert_ne!(first.profile.id, second.profile.id);
        assert_eq!(store.list().unwrap().len(), 2);
        assert_eq!(store.selected().unwrap(), Some(first.profile.id));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MIXED);
        assert_eq!(
            std::fs::read(store.directory(first.profile.id).join("profile.json")).unwrap(),
            before
        );
    }

    #[test]
    fn compatible_and_invalid_documents() {
        let source = "# keep comments\nmode: rule\nrules: ['MATCH,DIRECT']\n";
        let (yaml, warnings) = compatible_yaml(source).unwrap();
        assert_eq!(yaml, source);
        assert!(warnings.is_empty());
        for source in ["broken: [", "dmxlc3M6Ly9mb28=", "- list", ""] {
            assert!(compatible_yaml(source).is_err());
        }
        let (yaml, warnings) =
            compatible_yaml("proxies: [{name: ss, type: ss}]\nrules: ['MATCH,ss']").unwrap();
        assert!(crate::profiles::validate(&yaml).unwrap().proxies.is_empty());
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn subscriptions_and_nested_options_keep_compatible_values() {
        let source = r#"
external-controller: 0.0.0.0:9090
secret: keep-secret
unknown: true
dns: {enable: true, enhanced-mode: unsupported}
proxies:
  - name: ws
    type: vless
    server: example.com
    port: 443
    uuid: keep-uuid
    network: ws
    ws-opts: {path: /ws, unsupported: true}
"#;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::profiles::Store::new(dir.path().into()).unwrap();
        let result = store
            .import_subscription("订阅".into(), source, "https://example.com/sub".into())
            .unwrap();
        let profile = store.get(result.profile.id).unwrap();
        assert_eq!(profile.url.as_deref(), Some("https://example.com/sub"));
        let config = crate::profiles::validate(&profile.yaml).unwrap();
        assert_eq!(config.external_controller.as_deref(), Some("0.0.0.0:9090"));
        assert_eq!(config.secret, "keep-secret");
        assert!(config.dns.enable);
        assert_eq!(config.dns.enhanced_mode, "fake-ip");
        assert_eq!(config.proxies[0].ws_opts.path, "/ws");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.path == "proxies[0].ws-opts.unsupported")
        );
    }
}
