//! jq filters of rewrite modules (Surge `http-response-jq`, Loon
//! `response-body-json-jq`), run with jaq. Filters cannot read the
//! environment or other inputs.
use jaq_core::{
    Compiler, Ctx, Vars, data,
    load::{Arena, File, Loader},
    unwrap_valr,
};
use jaq_json::Val;
use std::{sync::Arc, time::Duration};

type Compiled = jaq_core::Filter<data::JustLut<Val>>;

/// How long one filter may run on one body.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Natives a module's filter must not reach: the process environment and
/// further inputs.
const BLOCKED: &[&str] = &["env", "input", "inputs"];

/// A compiled filter, shared by the connections that use it.
pub(crate) struct Filter(Arc<Compiled>);

impl Filter {
    pub(crate) fn compile(code: &str) -> Result<Self, String> {
        let defs = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs());
        let funs = jaq_core::funs()
            .chain(jaq_std::funs())
            .chain(jaq_json::funs())
            .filter(|f| !BLOCKED.contains(&f.0));
        let arena = Arena::default();
        let modules = Loader::new(defs)
            .load(&arena, File { code, path: () })
            .map_err(|_| "jq syntax error".to_owned())?;
        let filter = Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .map_err(|errors| {
                let names: Vec<String> = errors
                    .iter()
                    .flat_map(|(_, list)| list.iter().map(|(name, _)| name.to_string()))
                    .collect();
                format!("unknown jq names: {}", names.join(", "))
            })?;
        Ok(Self(Arc::new(filter)))
    }

    /// The body with the filter applied: its first output, as JSON. `None`
    /// when the body is not JSON, the filter fails, outputs nothing or runs
    /// too long.
    pub(crate) async fn apply(&self, body: Vec<u8>) -> Option<Vec<u8>> {
        let filter = self.0.clone();
        let task = tokio::task::spawn_blocking(move || run(&filter, &body));
        // A filter that never ends keeps its thread; the body passes as is.
        tokio::time::timeout(TIMEOUT, task).await.ok()?.ok()?
    }
}

fn run(filter: &Compiled, body: &[u8]) -> Option<Vec<u8>> {
    let input = jaq_json::read::parse_single(body).ok()?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let output = filter.id.run((ctx, input)).map(unwrap_valr).next()?.ok()?;
    Some(output.to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn applies_module_filters_and_keeps_inputs_out() {
        let cases = [
            (
                r#".heData |= map(select(.item.list[].bizType != "SceneListenCard"))"#,
                r#"{"heData":[{"item":{"list":[{"bizType":"SceneListenCard"}]}},{"item":{"list":[{"bizType":"X"}]}}]}"#,
                r#"{"heData":[{"item":{"list":[{"bizType":"X"}]}}]}"#,
            ),
            (
                r#"delpaths([["json","ad"]])"#,
                r#"{"json":{"ad":{"v":1},"qiji":2},"ret":0}"#,
                r#"{"json":{"qiji":2},"ret":0}"#,
            ),
            (
                r#".list |= map(select(.title | test("广告") | not))"#,
                r#"{"list":[{"title":"广告位"},{"title":"小说"}]}"#,
                r#"{"list":[{"title":"小说"}]}"#,
            ),
        ];
        for (code, input, expected) in cases {
            let filter = Filter::compile(code).unwrap();
            let output = filter.apply(input.as_bytes().to_vec()).await.unwrap();
            let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
            let expected: serde_json::Value = serde_json::from_str(expected).unwrap();
            assert_eq!(output, expected, "{code}");
        }
        assert!(Filter::compile(".a |=").is_err());
        for code in ["env", "$ENV", "input", "[inputs]"] {
            assert!(Filter::compile(code).is_err(), "{code}");
        }
        let filter = Filter::compile("del(.a)").unwrap();
        assert!(filter.apply(b"not json".to_vec()).await.is_none());
        let failing = Filter::compile("error(\"x\")").unwrap();
        assert!(failing.apply(b"{}".to_vec()).await.is_none());
    }
}
