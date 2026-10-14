//! YAML syntax checking for the configuration editors: the first error
//! with its position, so the apps can mark the line while the user types.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyntaxError {
    /// 1-based.
    pub line: usize,
    /// 1-based, in characters.
    pub column: usize,
    pub message: String,
}

/// The first YAML syntax error in `text`, or `None` when it parses. Only the
/// shape is checked: a document must be empty or a mapping at the top.
pub fn check(text: &str) -> Option<SyntaxError> {
    let value = match serde_yaml::from_str::<serde_yaml::Value>(text) {
        Ok(value) => value,
        Err(error) => {
            let (mut line, mut column) = error
                .location()
                .map_or((1, 1), |at| (at.line(), at.column()));
            // A duplicate is reported where its mapping starts; point at the repeat.
            if let Some(repeat) = duplicate(text, &error.to_string(), line) {
                (line, column) = (repeat, 1);
            }
            // libyaml blames a tab only in some positions; say so whenever
            // the line is indented with one.
            let tabbed = text
                .lines()
                .nth(line.saturating_sub(1))
                .is_some_and(|text| {
                    text.chars()
                        .take_while(|c| c.is_whitespace())
                        .any(|c| c == '\t')
                });
            let message = describe(&error.to_string());
            return Some(SyntaxError {
                line,
                column,
                message: if tabbed && !message.starts_with("缩进不能使用 Tab") {
                    format!("缩进不能使用 Tab，请改用空格（{}）", message)
                } else {
                    message
                },
            });
        }
    };
    match value {
        serde_yaml::Value::Null | serde_yaml::Value::Mapping(_) => None,
        serde_yaml::Value::Tagged(tagged)
            if matches!(tagged.value, serde_yaml::Value::Mapping(_)) =>
        {
            None
        }
        _ => {
            let line = text
                .lines()
                .position(|line| {
                    let line = line.trim();
                    !line.is_empty() && !line.starts_with('#') && line != "---"
                })
                .map_or(1, |index| index + 1);
            Some(SyntaxError {
                line,
                column: 1,
                message: "顶层应是「键: 值」形式的映射".into(),
            })
        }
    }
}

/// The line of the second `key:` at or after `from`, for "duplicate entry with key \"key\"".
fn duplicate(text: &str, error: &str, from: usize) -> Option<usize> {
    let key = error
        .strip_prefix("duplicate entry with key ")?
        .split(" at line ")
        .next()?;
    let key = key.trim_matches('"');
    let starts = |line: &str| {
        let line = line.trim_start().trim_start_matches("- ").trim_start();
        [
            format!("{key}:"),
            format!("\"{key}\":"),
            format!("'{key}':"),
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix.as_str()))
    };
    text.lines()
        .enumerate()
        .skip(from.saturating_sub(1))
        .filter(|(_, line)| starts(line))
        .nth(1)
        .map(|(index, _)| index + 1)
}

/// libyaml's wording in Chinese where a hint helps; the original otherwise.
fn describe(error: &str) -> String {
    // "... at line 3 column 5, while parsing ..." — the position is shown separately.
    let reason = error.split(" at line ").next().unwrap_or(error).trim();
    let hint = [
        ("found a tab character", "缩进不能使用 Tab"),
        (
            "found character that cannot start any token",
            "出现了不能作为开头的字符（如 Tab 缩进或 @、`），可给值加引号",
        ),
        (
            "mapping values are not allowed in this context",
            "这里不能出现「键: 值」，检查缩进，或给含冒号的值加引号",
        ),
        ("did not find expected key", "缩进不一致或缺少键"),
        ("did not find expected '-' indicator", "列表项缩进不一致"),
        (
            "did not find expected ',' or ']'",
            "方括号列表缺少「,」或「]」",
        ),
        (
            "did not find expected ',' or '}'",
            "花括号映射缺少「,」或「}」",
        ),
        ("could not find expected ':'", "缺少「:」"),
        ("found unexpected end of stream", "引号或括号没有闭合"),
        (
            "block sequence entries are not allowed",
            "这里不能开始列表项，检查缩进",
        ),
        ("duplicate entry", "键重复"),
        ("unknown anchor", "引用了不存在的锚点"),
        ("found undefined alias", "引用了不存在的锚点"),
    ]
    .into_iter()
    .find_map(|(english, chinese)| reason.starts_with(english).then_some(chinese));
    match hint {
        Some(hint) => format!("{hint}（{reason}）"),
        None => reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_configurations_and_empty_text() {
        for text in [
            "",
            "# only a comment\n",
            "mixed-port: 7890\nrules:\n  - MATCH,DIRECT\n",
            "proxies: [{name: a, type: vless}]\n",
        ] {
            assert_eq!(check(text), None, "{text:?}");
        }
    }

    #[test]
    fn locates_the_first_error() {
        let error = check("mode: rule\nproxies:\n  - name: a\n   type: vless\n").unwrap();
        assert_eq!((error.line, error.column), (4, 4), "{error:?}");
        assert!(error.message.starts_with("列表项缩进不一致"), "{error:?}");

        let error = check("a: b: c\n").unwrap();
        assert!(error.message.starts_with("这里不能出现"), "{error:?}");

        let error = check("mode: rule\nrules:\n\t- MATCH,DIRECT\n").unwrap();
        assert_eq!(error.line, 3, "{error:?}");
        assert!(error.message.starts_with("缩进不能使用 Tab"), "{error:?}");

        let error = check("a: 1\nproxies: [a, b\n").unwrap();
        assert!(error.line >= 2, "{error:?}");

        let error = check("mode: rule\nmode: global\n").unwrap();
        assert_eq!(error.line, 2, "{error:?}");
        assert!(error.message.starts_with("键重复"), "{error:?}");
    }

    #[test]
    fn wants_a_mapping_at_the_top() {
        let error = check("# header\n- a\n- b\n").unwrap();
        assert_eq!((error.line, error.column), (2, 1));
        assert!(check("just text").is_some());
    }
}
