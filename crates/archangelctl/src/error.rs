//! `archangelctl` error types.

/// Operator-CLI errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CtlError {
    /// Key generation / loading / persistence failure.
    #[error("key error: {0}")]
    Key(String),

    /// Reading the audit log failed.
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),
}
