//! Shared, fail-closed configuration for `archangeld` and `archangel-execd`.
//!
//! One schema, one validator, used by both daemons so the control plane
//! and the executor can never disagree about paths, sockets, or the
//! peer-credential gates. v0.1 parses only what this milestone enforces
//! and ignores forward-looking sections (rate limits, approval, snapshots,
//! egress) rather than pretending to enforce them.
//!
//! `validate()` is fail-closed: the daemons refuse to start with settings
//! that weaken security below the documented baseline. Anything we cannot
//! prove safe is a startup error, never a silent downgrade.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use serde::Deserialize;

use archangel_core::OperationMode;

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config: {0}")]
    Io(#[from] std::io::Error),
    /// The file was not valid TOML / had the wrong shape (this includes a
    /// missing required field such as `sockets.operator_uid`).
    #[error("invalid config syntax: {0}")]
    Parse(String),
    /// The config parsed but violates a security baseline.
    #[error("config rejected (fail-closed): {0}")]
    Invalid(String),
}

fn d_audit_key() -> PathBuf {
    "/etc/archangel/trust/audit.key".into()
}
fn d_operator_pub() -> PathBuf {
    "/etc/archangel/trust/operator.pub".into()
}
fn d_allowlist() -> PathBuf {
    "/etc/archangel/policies/allowlist.toml".into()
}
fn d_bundle_dir() -> PathBuf {
    "/etc/archangel/exec".into()
}
fn d_session_pub() -> PathBuf {
    "/run/archangel/session.pub".into()
}

/// `[daemon]`.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonCfg {
    /// Operator trust store: Ed25519 public keys allowed to sign `.exec`
    /// bundles and policies.
    pub trust_store: PathBuf,
    /// Append-only audit log path.
    pub audit_log: PathBuf,
    /// Persistent audit signing key (hex seed); generated `0600` if absent.
    #[serde(default = "d_audit_key")]
    pub audit_key: PathBuf,
    /// Pinned operator public key for boundary-A auth.
    #[serde(default = "d_operator_pub")]
    pub operator_pubkey: PathBuf,
    /// Allowlist TOML.
    #[serde(default = "d_allowlist")]
    pub allowlist: PathBuf,
    /// Directory of signed `.exec` bundles.
    #[serde(default = "d_bundle_dir")]
    pub bundle_dir: PathBuf,
    /// Where `archangeld` publishes its per-run session public key for the
    /// executor to read (rotated each daemon restart). A public key — its
    /// integrity is protected by the containing directory's permissions.
    #[serde(default = "d_session_pub")]
    pub session_pub: PathBuf,
}

const fn d_ctl_mode() -> u32 {
    0o660
}
fn d_ctl_group() -> String {
    "archangel".to_owned()
}

/// `[sockets]`.
#[derive(Debug, Clone, Deserialize)]
pub struct SocketsCfg {
    /// Operator control socket (boundary A).
    pub control: PathBuf,
    /// Control socket file mode (octal in TOML, e.g. `0o660`).
    #[serde(default = "d_ctl_mode")]
    pub control_mode: u32,
    /// Group that owns the control socket.
    #[serde(default = "d_ctl_group")]
    pub control_group: String,
    /// Executor socket (boundary B).
    pub exec: PathBuf,
    /// UID allowed to connect to the **control** socket (the operator).
    /// Required — there is no insecure default.
    pub operator_uid: u32,
    /// UID `archangeld` runs as; the executor only accepts **exec** socket
    /// connections from this UID. Required — no insecure default.
    pub daemon_uid: u32,
}

/// `[session]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionCfg {
    /// Per-task context isolation (#4).
    pub per_task_isolation: bool,
    /// Per-session lifetime in seconds.
    pub ttl_seconds: u64,
}

impl Default for SessionCfg {
    fn default() -> Self {
        Self {
            per_task_isolation: true,
            ttl_seconds: 3600,
        }
    }
}

/// `[modes]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ModesCfg {
    /// Default mode for new sessions.
    pub default: OperationMode,
    /// Whether autonomous mode is permitted on this host at all.
    pub autonomous_allowed: bool,
}

impl Default for ModesCfg {
    fn default() -> Self {
        Self {
            default: OperationMode::Interactive,
            autonomous_allowed: false,
        }
    }
}

/// `[llm]` (subset v0.1 uses).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmCfg {
    /// Active backend name (`anthropic` | `ollama`).
    pub default_backend: String,
    /// Model id. `None` lets the daemon pick a per-backend default.
    pub model: Option<String>,
    /// Max tokens per completion.
    pub max_tokens: u32,
}

impl Default for LlmCfg {
    fn default() -> Self {
        Self {
            default_backend: "ollama".to_owned(),
            model: None,
            max_tokens: 1024,
        }
    }
}

/// The parsed, validated configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// `[daemon]`.
    pub daemon: DaemonCfg,
    /// `[sockets]`.
    pub sockets: SocketsCfg,
    /// `[session]`.
    #[serde(default)]
    pub session: SessionCfg,
    /// `[modes]`.
    #[serde(default)]
    pub modes: ModesCfg,
    /// `[llm]`.
    #[serde(default)]
    pub llm: LlmCfg,
}

impl Config {
    /// Parse from a TOML string and validate (fail-closed).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load from a file and validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    /// Security baseline checks. Any failure is a refusal to start.
    fn validate(&self) -> Result<(), ConfigError> {
        let abs: [(&str, &Path); 8] = [
            ("daemon.trust_store", &self.daemon.trust_store),
            ("daemon.audit_log", &self.daemon.audit_log),
            ("daemon.audit_key", &self.daemon.audit_key),
            ("daemon.operator_pubkey", &self.daemon.operator_pubkey),
            ("daemon.allowlist", &self.daemon.allowlist),
            ("daemon.bundle_dir", &self.daemon.bundle_dir),
            ("sockets.control", &self.sockets.control),
            ("sockets.exec", &self.sockets.exec),
        ];
        for (label, p) in abs {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "{label} must be an absolute path, got {}",
                    p.display()
                )));
            }
        }
        if !self.daemon.session_pub.is_absolute() {
            return Err(ConfigError::Invalid(
                "daemon.session_pub must be an absolute path".to_owned(),
            ));
        }

        if self.sockets.control_mode & 0o007 != 0 {
            return Err(ConfigError::Invalid(format!(
                "sockets.control_mode {:#o} grants access to 'other'; the \
                 control socket must be owner/group only",
                self.sockets.control_mode
            )));
        }

        if self.modes.default == OperationMode::Autonomous && !self.modes.autonomous_allowed {
            return Err(ConfigError::Invalid(
                "modes.default = autonomous but modes.autonomous_allowed = false".to_owned(),
            ));
        }

        match self.llm.default_backend.as_str() {
            "anthropic" | "ollama" => {}
            other => {
                return Err(ConfigError::Invalid(format!(
                    "llm.default_backend {other:?} is not supported (anthropic|ollama)"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_core::OperationMode;

    use super::Config;

    const MINIMAL: &str = r#"
[daemon]
trust_store = "/etc/archangel/trust/operators.pubkeys"
audit_log   = "/var/log/archangel/audit.log.jsonl"

[sockets]
control      = "/run/archangel/ctl.sock"
control_mode = 0o660
exec         = "/run/archangel/exec.sock"
operator_uid = 1000
daemon_uid   = 1000
"#;

    #[test]
    fn minimal_valid_config_parses_with_defaults() {
        let c = Config::from_toml(MINIMAL).expect("valid");
        assert_eq!(c.modes.default, OperationMode::Interactive);
        assert!(!c.modes.autonomous_allowed);
        assert!(c.session.per_task_isolation);
        assert_eq!(c.sockets.operator_uid, 1000);
        assert_eq!(
            c.daemon.session_pub.to_str(),
            Some("/run/archangel/session.pub")
        );
        assert_eq!(c.llm.default_backend, "ollama");
    }

    #[test]
    fn missing_operator_uid_is_rejected() {
        let bad = MINIMAL.replace("operator_uid = 1000\n", "");
        assert!(Config::from_toml(&bad).is_err(), "uid is required");
    }

    #[test]
    fn relative_path_is_refused() {
        let bad = MINIMAL.replace("/var/log/archangel/audit.log.jsonl", "var/log/audit.jsonl");
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn world_accessible_control_socket_is_refused() {
        let bad = MINIMAL.replace("0o660", "0o666");
        let e = Config::from_toml(&bad).expect_err("reject");
        assert!(format!("{e}").contains("other"));
    }

    #[test]
    fn autonomous_default_without_optin_is_refused() {
        let bad = format!("{MINIMAL}\n[modes]\ndefault=\"autonomous\"\nautonomous_allowed=false\n");
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn unsupported_backend_is_refused() {
        let bad = format!("{MINIMAL}\n[llm]\ndefault_backend=\"gpt5\"\n");
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn forward_looking_sections_are_ignored() {
        let f = format!(
            "{MINIMAL}\n[rate_limits]\nactions_per_minute=20\n\
             [egress]\ndefault_policy=\"deny\"\n"
        );
        assert!(Config::from_toml(&f).is_ok());
    }
}
