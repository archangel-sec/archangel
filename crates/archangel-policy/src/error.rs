//! Policy subsystem error types.

/// Errors produced by the policy engine.
///
/// Note: a *denial* is not an error — it is a normal [`crate::Decision`].
/// These variants are for failures that prevent a decision from being made
/// at all. The caller MUST treat any such failure as fail-closed (deny).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The allowlist file could not be read.
    #[error("cannot read allowlist file: {0}")]
    Io(#[from] std::io::Error),

    /// The allowlist file is not valid TOML or has the wrong shape.
    #[error("invalid allowlist: {0}")]
    AllowlistParse(String),

    /// A path could not be normalized for matching (e.g. not absolute,
    /// or contains an embedded NUL). Such a path is rejected, never allowed.
    #[error("unnormalizable path: {0}")]
    BadPath(String),
}
