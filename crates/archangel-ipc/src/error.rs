//! IPC protocol error types.

/// Errors at trust boundary B (daemon ↔ executor).
///
/// Every variant is a hard rejection. The executor must treat any error
/// here as "do not execute" — there is no degraded/best-effort path across
/// this boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// Protocol version of the envelope is not one this build accepts.
    #[error("unsupported IPC protocol version {got} (this build speaks {expected})")]
    VersionMismatch {
        /// Version seen on the wire.
        got: u16,
        /// Version this build speaks.
        expected: u16,
    },

    /// CBOR (de)serialization failed.
    #[error("IPC codec error: {0}")]
    Codec(String),

    /// The signature field was not the expected 64 bytes.
    #[error("signature is malformed (expected 64 bytes, got {0})")]
    BadSignatureLen(usize),

    /// The Ed25519 signature did not verify against the session key.
    ///
    /// This is the core boundary-B rejection: a request the executor
    /// cannot prove came from the daemon holding the current session key
    /// is never executed.
    #[error("session signature verification failed")]
    SignatureInvalid,

    /// A length-prefixed frame was malformed or exceeded the size limit.
    #[error("framing error: {0}")]
    Framing(String),
}
