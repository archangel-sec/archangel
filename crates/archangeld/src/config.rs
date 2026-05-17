//! Daemon configuration (`/etc/archangel/archangel.toml`).
//!
//! v0.1 parses only the sections this milestone actually enforces and
//! ignores the forward-looking ones (rate limits, approval, snapshots,
//! egress) — they are validated by the layers that own them when those
//! land, not pretended here.
//!
//! `validate()` is **fail-closed**: the daemon refuses to start with
//! settings that weaken security below the documented baseline (per the
//! example config's own promise). A config we cannot prove safe is a
//! startup error, never a silent downgrade.

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
    /// The file was not valid TOML / had the wrong shape.
    #[error("invalid config syntax: {0}")]
    Parse(String),
    /// The config parsed but violates a security baseline.
    #[error("config rejected (fail-closed): {0}")]
    Invalid(String),
}

/// `[daemon]`.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonCfg {
    /// Operator trust store: Ed25519 public keys allowed to sign `.exec`
    /// bundles and policies.
    pub trust_store: PathBuf,
    /// Append-only audit log path.
    pub audit_log: PathBuf,
}

/// `[sockets]`.
#[derive(Debug, Clone, Deserialize)]
pub struct SocketsCfg {
    /// Operator control socket (boundary A).
    pub control: PathBuf,
    /// Control socket file mode (octal in TOML, e.g. `0o660`).
    #[serde(default = "default_ctl_mode")]
    pub control_mode: u32,
    /// Group that owns the control socket.
    #[serde(default = "default_ctl_group")]
    pub control_group: String,
    /// Executor socket (boundary B).
    pub exec: PathBuf,
}

const fn default_ctl_mode() -> u32 {
    0o660
}
fn default_ctl_group() -> String {
    "archangel".to_owned()
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
        // Conservative: interactive by default, autonomous opt-in only.
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
    /// Active backend name.
    pub default_backend: String,
}

impl Default for LlmCfg {
    fn default() -> Self {
        Self {
            default_backend: "ollama".to_owned(),
        }
    }
}

/// The parsed, validated daemon configuration.
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
        let cfg: Self =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load from a file and validate.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    /// Security baseline checks. Any failure is a refusal to start.
    fn validate(&self) -> Result<(), ConfigError> {
        for (label, p) in [
            ("daemon.trust_store", &self.daemon.trust_store),
            ("daemon.audit_log", &self.daemon.audit_log),
            ("sockets.control", &self.sockets.control),
            ("sockets.exec", &self.sockets.exec),
        ] {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "{label} must be an absolute path, got {}",
                    p.display()
                )));
            }
        }

        // A world-accessible control socket would let any local user drive
        // the daemon. Refuse any "other" permission bit.
        if self.sockets.control_mode & 0o007 != 0 {
            return Err(ConfigError::Invalid(format!(
                "sockets.control_mode {:#o} grants access to 'other'; \
                 the control socket must be owner/group only",
                self.sockets.control_mode
            )));
        }

        // Autonomous default is only allowed if autonomous is enabled.
        if self.modes.default == OperationMode::Autonomous
            && !self.modes.autonomous_allowed
        {
            return Err(ConfigError::Invalid(
                "modes.default = autonomous but modes.autonomous_allowed = false"
                    .to_owned(),
            ));
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
audit_log = "/var/log/archangel/audit.log.jsonl"

[sockets]
control = "/run/archangel/ctl.sock"
control_mode = 0o660
exec = "/run/archangel/exec.sock"
"#;

    #[test]
    fn minimal_valid_config_parses_with_conservative_defaults() {
        let c = Config::from_toml(MINIMAL).expect("valid");
        assert_eq!(c.modes.default, OperationMode::Interactive);
        assert!(!c.modes.autonomous_allowed);
        assert!(c.session.per_task_isolation);
    }

    #[test]
    fn relative_paths_are_refused() {
        let bad = MINIMAL.replace(
            "/var/log/archangel/audit.log.jsonl",
            "var/log/archangel/audit.log.jsonl",
        );
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn world_accessible_control_socket_is_refused() {
        let bad = MINIMAL.replace("0o660", "0o666");
        let err = Config::from_toml(&bad).expect_err("must reject");
        assert!(format!("{err}").contains("other"));
    }

    #[test]
    fn autonomous_default_without_optin_is_refused() {
        let bad = format!(
            "{MINIMAL}\n[modes]\ndefault = \"autonomous\"\nautonomous_allowed = false\n"
        );
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn autonomous_default_with_optin_is_allowed() {
        let ok = format!(
            "{MINIMAL}\n[modes]\ndefault = \"autonomous\"\nautonomous_allowed = true\n"
        );
        let c = Config::from_toml(&ok).expect("valid");
        assert_eq!(c.modes.default, OperationMode::Autonomous);
    }

    #[test]
    fn forward_looking_sections_are_ignored_not_rejected() {
        // The documented example has sections v0.1 does not enforce yet;
        // they must not break startup.
        let with_future = format!(
            "{MINIMAL}\n[rate_limits]\nactions_per_minute = 20\n\
             [egress]\ndefault_policy = \"deny\"\n"
        );
        assert!(Config::from_toml(&with_future).is_ok());
    }

    #[test]
    fn invalid_toml_is_error() {
        assert!(Config::from_toml("this is = = not toml").is_err());
    }
}
