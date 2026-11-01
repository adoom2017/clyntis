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
                message: if tabbed && !message.starts_with("tabs cannot indent") {
                    format!("tabs cannot indent YAML; use spaces ({})", message)
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
                message: "the top level must be a mapping of key: value".into(),
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
        ("found a tab character", "tabs cannot indent YAML"),
        (
            "found character that cannot start any token",
            "a character that cannot start a value (such as a tab, @ or `); quote the value",
        ),
        (
            "mapping values are not allowed in this context",
            "key: value is not allowed here; check the indentation or quote a value containing a colon",
        ),
        ("did not find expected key", "inconsistent indentation or a missing key"),
        ("did not find expected '-' indicator", "list items are indented inconsistently"),
        (
            "did not find expected ',' or ']'",
            "a [list] is missing , or ]",
        ),
        (
            "did not find expected ',' or '}'",
            "a {mapping} is missing , or }",
        ),
        ("could not find expected ':'", "missing :"),
        ("found unexpected end of stream", "an unclosed quote or bracket"),
        (
            "block sequence entries are not allowed",
            "a list item cannot start here; check the indentation",
        ),
        ("duplicate entry", "duplicate key"),
        ("unknown anchor", "refers to an anchor that does not exist"),
        ("found undefined alias", "refers to an anchor that does not exist"),
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
        assert!(
            error.message.starts_with("list items are indented"),
            "{error:?}"
        );

        let error = check("a: b: c\n").unwrap();
        assert!(
            error.message.starts_with("key: value is not allowed"),
            "{error:?}"
        );

        let error = check("mode: rule\nrules:\n\t- MATCH,DIRECT\n").unwrap();
        assert_eq!(error.line, 3, "{error:?}");
        assert!(error.message.starts_with("tabs cannot indent"), "{error:?}");

        let error = check("a: 1\nproxies: [a, b\n").unwrap();
        assert!(error.line >= 2, "{error:?}");

        let error = check("mode: rule\nmode: global\n").unwrap();
        assert_eq!(error.line, 2, "{error:?}");
        assert!(error.message.starts_with("duplicate key"), "{error:?}");
    }

    #[test]
    fn wants_a_mapping_at_the_top() {
        let error = check("# header\n- a\n- b\n").unwrap();
        assert_eq!((error.line, error.column), (2, 1));
        assert!(check("just text").is_some());
    }
}
