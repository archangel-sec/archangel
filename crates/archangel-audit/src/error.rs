//! Audit subsystem error types.

/// Errors produced by the audit log writer and verifier.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// An I/O error occurred while opening, appending to, or reading the log.
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A log line could not be (de)serialized as a JSON audit entry.
    #[error("audit entry serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A hex-encoded field was malformed.
    #[error("invalid hex encoding: {0}")]
    Hex(String),

    /// A cryptographic key or signature was malformed.
    #[error("invalid cryptographic material: {0}")]
    Crypto(String),

    /// Chain verification failed. This means the log was tampered with,
    /// truncated, reordered, or signed by an unexpected key.
    #[error("audit chain verification failed at sequence {seq}: {reason}")]
    ChainBroken {
        /// Sequence number of the first entry that failed verification.
        seq: u64,
        /// Human-readable explanation of the failure.
        reason: String,
    },

    /// The log file was empty when at least a genesis entry was expected.
    #[error("audit log is empty (no genesis entry)")]
    Empty,
}
