//! Snapshot subsystem errors.

/// Why a snapshot operation could not be performed.
///
/// Every variant is fail-closed at the call site: a mutating action whose
/// recovery point could not be created MUST NOT run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// No snapshot backend is available for the target path (e.g. the
    /// filesystem is not BTRFS). The caller must refuse the mutating
    /// action — there is no recovery point.
    #[error("no snapshot backend for {0}")]
    NoBackend(String),

    /// The backend command failed (non-zero exit / spawn error). Stderr
    /// is captured (truncated) for diagnostics.
    #[error("snapshot backend failed: {0}")]
    BackendFailed(String),

    /// An operation this build does not perform automatically yet.
    #[error("unsupported in this build: {0}")]
    Unsupported(String),

    /// Underlying I/O failure.
    #[error("snapshot I/O error: {0}")]
    Io(String),
}
