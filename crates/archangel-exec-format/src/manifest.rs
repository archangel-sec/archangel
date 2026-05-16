//! Typed `.exec` manifest and its parser.
//!
//! Parsing is `#[serde(deny_unknown_fields)]` everywhere: an unknown key in
//! a signed bundle is a *rejection*, not something to ignore. A future
//! archangel must never silently skip a field a newer bundle added — that
//! could hide an escalation. New fields require a deliberate code change.

use std::collections::BTreeMap;

use serde::Deserialize;

use archangel_core::RiskLevel;

/// A fully parsed `.exec` manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecManifest {
    /// Identity and risk metadata.
    pub meta: Meta,
    /// Declared argument schema (layer #7). Empty if the bundle takes none.
    #[serde(default)]
    pub args: BTreeMap<String, ArgSpec>,
    /// Declarative sandbox profile. The executor *builds* this; the bundle
    /// cannot escalate by editing it (mismatch is caught at execution time).
    pub sandbox: SandboxSpec,
    /// The script/binary to run.
    pub payload: Payload,
    /// Optional post-execution health check.
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

/// `[meta]` — identity and risk classification.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// Bundle name (must equal the file stem; checked by the loader).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Risk level. `critical` triggers the two-person rule in every mode.
    pub risk: RiskLevel,
    /// If true, the bundle performs no mutation and may run in read-only
    /// mode. The executor still enforces this structurally.
    pub read_only: bool,
    /// If true, a filesystem snapshot is taken before execution (#16).
    #[serde(default)]
    pub mutates_persistent_state: bool,
    /// If true, the action needs network egress (subject to the filter #17).
    #[serde(default)]
    pub requires_network: bool,
}

/// One entry in the `[args]` schema.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgSpec {
    /// Value type. v0.1 supports only `string`.
    #[serde(rename = "type")]
    pub ty: ArgType,
    /// Optional pattern the value must fully match. The validator anchors
    /// it (`\A(?:...)\z`) so a partial match cannot smuggle a value.
    #[serde(default)]
    pub regex: Option<String>,
    /// Whether the argument must be supplied.
    #[serde(default)]
    pub required: bool,
}

/// Supported argument value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArgType {
    /// A UTF-8 string, optionally constrained by `regex`.
    String,
}

/// `[sandbox]` — declarative isolation profile (consumed by the executor).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    /// Linux capabilities to grant (empty = none; the default).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Paths mountable read-only inside the sandbox.
    #[serde(default)]
    pub allowed_paths_ro: Vec<String>,
    /// Paths mountable read-write inside the sandbox.
    #[serde(default)]
    pub allowed_paths_rw: Vec<String>,
    /// Named seccomp syscall profile to install.
    pub syscall_profile: String,
    /// Network policy for the action's network namespace.
    pub network: NetworkPolicy,
    /// Optional CPU ceiling (cgroup), e.g. `"10%"`.
    #[serde(default)]
    pub cpu_max: Option<String>,
    /// Optional memory ceiling (cgroup), e.g. `"128M"`.
    #[serde(default)]
    pub memory_max: Option<String>,
    /// Hard wall-clock timeout in seconds.
    pub timeout_seconds: u32,
}

/// Network policy declared by a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkPolicy {
    /// No network namespace access at all (default-safe).
    None,
    /// Loopback only.
    Loopback,
    /// Egress permitted, still subject to the kernel egress filter (#17).
    Egress,
}

/// Payload kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PayloadType {
    /// A bash script.
    Bash,
}

/// `[payload]` — what actually runs. The `sha256` binds the payload to the
/// signed manifest: changing the payload invalidates the signature.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Payload kind. v0.1 supports only `bash`.
    #[serde(rename = "type")]
    pub ty: PayloadType,
    /// Lowercase hex SHA-256 of the payload bytes.
    pub sha256: String,
    /// Inline payload source (v0.1 only supports inline payloads).
    pub inline: String,
}

/// `[health_check]` — optional post-action verification (#16 rollback hook).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    /// Command template (may reference `{{ args.* }}`).
    pub command: String,
    /// Expected exit code for "healthy".
    pub expect_exit: i32,
    /// Health-check timeout in seconds.
    pub timeout_seconds: u32,
}

impl ExecManifest {
    /// Parse a manifest from already-authenticated TOML bytes.
    ///
    /// Caller contract: the bytes MUST have already had their signature
    /// verified ([`crate::VerifiedBundle`] enforces this ordering). Parsing
    /// is still attack surface; we keep it strict and total.
    pub(crate) fn parse(toml_bytes: &[u8]) -> Result<Self, crate::ExecFormatError> {
        let text = std::str::from_utf8(toml_bytes)
            .map_err(|e| crate::ExecFormatError::BadManifest(format!("not UTF-8: {e}")))?;
        toml::from_str(text)
            .map_err(|e| crate::ExecFormatError::BadManifest(e.to_string()))
    }
}
