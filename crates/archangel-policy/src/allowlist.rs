//! Simple per-profile allowlist loader (v0.1).
//!
//! The allowlist names which `.exec` bundles an LLM may invoke, per profile
//! and per mode. It is the *permissive* half of policy: the denylist says
//! what may never happen; the allowlist says what is explicitly permitted.
//! Both must agree — denylist first and authoritative, then allowlist.
//!
//! v0.1 is intentionally minimal: parse TOML, look things up, fail closed.
//! Cryptographic signing/verification of the allowlist bundle is a later
//! milestone (v0.3, threat model layer #9); this loader does NOT establish
//! authenticity and must only be fed a file the daemon already trusts by
//! filesystem permissions.

use serde::Deserialize;

use archangel_core::OperationMode;

use crate::error::PolicyError;

/// One profile's permitted actions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProfileAllow {
    /// Profile name (selected at session start).
    pub name: String,
    /// Mode this profile runs in.
    pub mode: OperationMode,
    /// Names of `.exec` bundles permitted in this profile.
    #[serde(default)]
    pub allowed_exec: Vec<String>,
}

/// A parsed allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Allowlist {
    /// All configured profiles.
    #[serde(default, rename = "profile")]
    pub profiles: Vec<ProfileAllow>,
}

impl Allowlist {
    /// Parse an allowlist from a TOML string.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        toml::from_str(text).map_err(|e| PolicyError::AllowlistParse(e.to_string()))
    }

    /// Load an allowlist from a file path.
    pub fn load(path: &std::path::Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    /// Look up a profile by name.
    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&ProfileAllow> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Return `true` only if `exec` is explicitly permitted in `profile`
    /// **and** that profile runs in `mode`.
    ///
    /// Fail-closed: an unknown profile, a mode mismatch, or an exec not in
    /// the list all return `false`.
    #[must_use]
    pub fn is_allowed(&self, profile: &str, exec: &str, mode: OperationMode) -> bool {
        self.profile(profile).is_some_and(|p| {
            p.mode == mode && p.allowed_exec.iter().any(|e| e == exec)
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_core::OperationMode;

    use super::Allowlist;

    const SAMPLE: &str = r#"
[[profile]]
name = "default"
mode = "read_only"
allowed_exec = ["list-services", "read-logs"]

[[profile]]
name = "ops"
mode = "interactive"
allowed_exec = ["restart-service"]
"#;

    #[test]
    fn parses_and_looks_up() {
        let al = Allowlist::from_toml(SAMPLE).expect("valid toml");
        assert!(al.is_allowed("default", "list-services", OperationMode::ReadOnly));
        assert!(al.is_allowed("ops", "restart-service", OperationMode::Interactive));
    }

    #[test]
    fn unknown_profile_fails_closed() {
        let al = Allowlist::from_toml(SAMPLE).expect("valid toml");
        assert!(!al.is_allowed("nope", "list-services", OperationMode::ReadOnly));
    }

    #[test]
    fn mode_mismatch_fails_closed() {
        let al = Allowlist::from_toml(SAMPLE).expect("valid toml");
        // Correct exec and profile, but wrong mode.
        assert!(!al.is_allowed("default", "list-services", OperationMode::Autonomous));
    }

    #[test]
    fn exec_not_listed_fails_closed() {
        let al = Allowlist::from_toml(SAMPLE).expect("valid toml");
        assert!(!al.is_allowed("default", "rm-rf-everything", OperationMode::ReadOnly));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let al = Allowlist::from_toml("").expect("empty is valid");
        assert!(!al.is_allowed("default", "anything", OperationMode::ReadOnly));
    }

    #[test]
    fn invalid_toml_is_error() {
        assert!(Allowlist::from_toml("this is not = = toml").is_err());
    }
}
