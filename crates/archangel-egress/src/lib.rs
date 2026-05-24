//! Egress allowlist policy — threat-model **layer #17**.
//!
//! This crate is the *decision* half of egress control: given a destination
//! `(host, port)`, is the connection permitted? It is pure, deterministic,
//! and fail-closed — the default posture is **deny**, and a destination is
//! allowed only if it matches an explicit allowlist entry.
//!
//! Enforcement (making a denied connection *structurally impossible* rather
//! than merely "decided against") is a separate concern layered on top: the
//! daemon's network is confined so it can only reach allowlisted endpoints
//! (e.g. a systemd `IPAddressAllow=` set generated from the resolved
//! allowlist, or an egress proxy), and sandboxed actions are already denied
//! socket creation at the syscall level by the seccomp profile (#11) unless
//! their bundle opts into networking. See `docs/EGRESS.md`. Keeping the
//! decision here, isolated and tested, is what lets that enforcement be a
//! thin, auditable shell.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Why an egress configuration was rejected. Fail-closed: a configuration we
/// cannot parse unambiguously is refused, never interpreted loosely.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressError {
    /// `default_policy` was neither `deny` nor `allow`.
    #[error("invalid egress default_policy {0:?} (expected \"deny\" or \"allow\")")]
    BadDefaultPolicy(String),

    /// An `allow` entry could not be parsed as `host` or `host:port`.
    #[error("invalid egress allow entry {entry:?}: {why}")]
    BadRule {
        /// The offending entry.
        entry: String,
        /// What was wrong with it.
        why: String,
    },
}

/// One allowlist entry: a host, optionally pinned to a single port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EgressRule {
    /// Lowercased hostname or IPv4 literal.
    host: String,
    /// `None` ⇒ any port; `Some(p)` ⇒ only port `p`.
    port: Option<u16>,
}

/// A compiled egress allowlist.
///
/// Built from a `default_policy` (`deny` is the secure default) and a list of
/// `host` / `host:port` entries. [`EgressPolicy::is_allowed`] is the
/// fail-closed decision used at every outbound connection.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// `true` only when `default_policy = "allow"` — permits everything.
    /// Intended for local development; never the default.
    allow_all: bool,
    rules: Vec<EgressRule>,
}

/// Hostnames/IPv4 only for v1: lowercase letters, digits, `.` and `-`. This
/// deliberately rejects whitespace, control characters, and IPv6 literals
/// (which contain `:` and need bracket syntax) — anything ambiguous is
/// refused rather than guessed at.
fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn parse_rule(raw: &str) -> Result<EgressRule, EgressError> {
    let entry = raw.trim();
    let bad = |why: &str| EgressError::BadRule {
        entry: entry.to_owned(),
        why: why.to_owned(),
    };
    if entry.is_empty() {
        return Err(bad("empty"));
    }
    // Split a trailing `:port` (rightmost colon). A remaining colon in the
    // host means an IPv6 literal or junk — rejected (unsupported in v1).
    if let Some((host, port_str)) = entry.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| bad("port after ':' is not a valid 1..=65535 number"))?;
        if port == 0 {
            return Err(bad("port 0 is not valid"));
        }
        let host = host.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(bad(
                "host part is empty, too long, or has illegal characters (IPv6 is unsupported)",
            ));
        }
        Ok(EgressRule {
            host,
            port: Some(port),
        })
    } else {
        let host = entry.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(bad("host is too long or has illegal characters"));
        }
        Ok(EgressRule { host, port: None })
    }
}

impl EgressPolicy {
    /// Compile a policy from `default_policy` (`"deny"`/`"allow"`) and the
    /// `allow` entries.
    ///
    /// # Errors
    /// [`EgressError::BadDefaultPolicy`] or [`EgressError::BadRule`].
    /// Fail-closed: any malformed input is refused.
    pub fn new<S: AsRef<str>>(default_policy: &str, allow: &[S]) -> Result<Self, EgressError> {
        let allow_all = match default_policy.trim().to_ascii_lowercase().as_str() {
            "deny" => false,
            "allow" => true,
            other => return Err(EgressError::BadDefaultPolicy(other.to_owned())),
        };
        let rules = allow
            .iter()
            .map(|e| parse_rule(e.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { allow_all, rules })
    }

    /// A deny-all policy (no egress permitted). The safest possible posture.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allow_all: false,
            rules: Vec::new(),
        }
    }

    /// Whether a connection to `host:port` is permitted. Fail-closed: unless
    /// the policy is `allow`-all or an entry matches, the answer is `false`.
    /// Host comparison is case-insensitive and exact (no implicit subdomain
    /// matching).
    #[must_use]
    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        if self.allow_all {
            return true;
        }
        let host = host.trim().to_ascii_lowercase();
        self.rules
            .iter()
            .any(|r| r.host == host && r.port.is_none_or(|p| p == port))
    }

    /// True if this policy permits everything (`default_policy = "allow"`).
    /// Callers should warn loudly when this is set.
    #[must_use]
    pub const fn is_allow_all(&self) -> bool {
        self.allow_all
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{EgressError, EgressPolicy};

    #[test]
    fn deny_all_blocks_everything() {
        let p = EgressPolicy::deny_all();
        assert!(!p.is_allowed("api.anthropic.com", 443));
        assert!(!p.is_allowed("127.0.0.1", 11434));

        let p2 = EgressPolicy::new("deny", &[] as &[&str]).expect("valid");
        assert!(!p2.is_allowed("anything", 443));
    }

    #[test]
    fn host_entry_allows_any_port_exact_host_only() {
        let p = EgressPolicy::new("deny", &["api.anthropic.com"]).expect("valid");
        assert!(p.is_allowed("api.anthropic.com", 443));
        assert!(
            p.is_allowed("api.anthropic.com", 8443),
            "no port ⇒ any port"
        );
        // Exact match: a different host or a subdomain is NOT implied.
        assert!(!p.is_allowed("evil.com", 443));
        assert!(!p.is_allowed("api.anthropic.com.evil.com", 443));
        assert!(!p.is_allowed("anthropic.com", 443));
    }

    #[test]
    fn host_port_entry_pins_the_port() {
        let p = EgressPolicy::new("deny", &["127.0.0.1:11434"]).expect("valid");
        assert!(p.is_allowed("127.0.0.1", 11434));
        assert!(!p.is_allowed("127.0.0.1", 443), "wrong port ⇒ denied");
    }

    #[test]
    fn matching_is_case_insensitive() {
        let p = EgressPolicy::new("deny", &["API.Anthropic.COM"]).expect("valid");
        assert!(p.is_allowed("api.anthropic.com", 443));
        assert!(p.is_allowed("Api.Anthropic.Com", 443));
    }

    #[test]
    fn allow_all_permits_everything() {
        let p = EgressPolicy::new("allow", &[] as &[&str]).expect("valid");
        assert!(p.is_allow_all());
        assert!(p.is_allowed("literally-anywhere.example", 1));
    }

    #[test]
    fn bad_default_policy_is_refused() {
        assert_eq!(
            EgressPolicy::new("permit", &[] as &[&str]).unwrap_err(),
            EgressError::BadDefaultPolicy("permit".to_owned())
        );
    }

    #[test]
    fn malformed_rules_are_refused_fail_closed() {
        for bad in [
            "",                  // empty
            "host:notaport",     // non-numeric port
            "host:0",            // port 0
            "host:99999",        // port out of range
            "::1",               // IPv6 literal (unsupported)
            "[2001:db8::1]:443", // bracketed IPv6 (unsupported)
            "has space.com",     // illegal char
            "host:",             // empty port
        ] {
            assert!(
                matches!(
                    EgressPolicy::new("deny", &[bad]),
                    Err(EgressError::BadRule { .. })
                ),
                "entry {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn multiple_rules_combine() {
        let p =
            EgressPolicy::new("deny", &["api.anthropic.com", "127.0.0.1:11434"]).expect("valid");
        assert!(p.is_allowed("api.anthropic.com", 443));
        assert!(p.is_allowed("127.0.0.1", 11434));
        assert!(!p.is_allowed("127.0.0.1", 22));
        assert!(!p.is_allowed("github.com", 443));
    }
}
