//! HTTPS decryption (MITM) for inspecting what apps request: connections to
//! the listed hosts are decrypted with certificates signed by a local CA the
//! user trusts, and their HTTP requests are recorded.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Mitm {
    pub enable: bool,
    /// Host patterns to decrypt: `*` matches any characters (dots too), `?`
    /// one; a leading `-` excludes the hosts it matches, whatever else
    /// matches them.
    pub hostname: Vec<String>,
    /// The CA certificate (PEM) that signs the per-host certificates.
    pub ca_cert: String,
    /// Its private key (PEM). Never exported by the controller.
    #[serde(skip_serializing)]
    pub ca_key: String,
    /// Also decrypt servers whose certificate chain verifies but whose names
    /// do not strictly cover the host: a wildcard such as `*.example.com`
    /// for `a.b.example.com`, which some apps accept. Off: those servers are
    /// passed through.
    pub lenient_upstream: bool,
}

/// Whether a certificate for `names` covers `host` under the lenient rule:
/// a name equal to it, or a wildcard `*.domain` with `host` anywhere below
/// `domain` (not only one level, as TLS requires).
pub fn loosely_covers(names: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|name| {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        match name.strip_prefix("*.") {
            // At least two labels, so `*.com` covers nothing.
            Some(domain) if domain.contains('.') => host.ends_with(&format!(".{domain}")),
            Some(_) => false,
            None => name == host,
        }
    })
}

impl Mitm {
    /// Whether `host` is to be decrypted (ignores `enable`).
    pub fn matches(&self, host: &str) -> bool {
        host_matches(&self.hostname, host)
    }
}

/// Whether `host` matches the patterns: one including pattern matches and no
/// `-` pattern does.
pub fn host_matches(patterns: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut included = false;
    for pattern in patterns {
        let pattern = pattern.trim();
        if let Some(excluded) = pattern.strip_prefix('-') {
            if wildcard(excluded.trim(), &host) {
                return false;
            }
        } else if !pattern.is_empty() && !included {
            included = wildcard(pattern, &host);
        }
    }
    included
}

/// `*` matches any run of characters, `?` one character; case-insensitive.
fn wildcard(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let (p, h) = (pattern.as_bytes(), host.as_bytes());
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < h.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == h[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some((i, j));
            i += 1;
        } else if let Some((si, sj)) = star {
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lenient_names_cover_deeper_hosts() {
        let names = list(&["*.ximalaya.com", "ximalaya.com"]);
        assert!(loosely_covers(&names, "new.c.ximalaya.com"));
        assert!(loosely_covers(&names, "a.ximalaya.com"));
        assert!(loosely_covers(&names, "XIMALAYA.com."));
        assert!(!loosely_covers(&names, "ximalaya.com.evil.test"));
        assert!(!loosely_covers(&names, "notximalaya.com"));
        assert!(!loosely_covers(&list(&["*.com"]), "a.b.com"));
    }

    #[test]
    fn wildcards_and_exclusions() {
        let patterns = list(&["*.biliapi.net", "api.example.com", "*", "-*.apple.com"]);
        assert!(host_matches(&patterns, "app.biliapi.net"));
        assert!(host_matches(&patterns, "API.Example.com."));
        assert!(host_matches(&patterns, "anything.test"));
        assert!(!host_matches(&patterns, "gs.apple.com"));
        let patterns = list(&["*pcdn*.biliapi.net", "a?c.test"]);
        assert!(host_matches(&patterns, "xy-pcdn-1.biliapi.net"));
        assert!(!host_matches(&patterns, "biliapi.net"));
        assert!(host_matches(&patterns, "abc.test"));
        assert!(!host_matches(&patterns, "abbc.test"));
        assert!(!host_matches(&[], "example.com"));
        assert!(!host_matches(&list(&["-*"]), "example.com"));
    }
}
