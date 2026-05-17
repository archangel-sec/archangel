//! Boundary-A protocol error types.

/// Errors at trust boundary A (operator ↔ daemon).
///
/// Every variant is a hard rejection. The daemon must treat any error here
/// as "do not act on this request"; there is no degraded path across the
/// control plane.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CtlError {
    /// Envelope protocol version is not one this build accepts.
    #[error("unsupported control protocol version {got} (this build speaks {expected})")]
    VersionMismatch {
        /// Version seen on the wire.
        got: u16,
        /// Version this build speaks.
        expected: u16,
    },

    /// CBOR (de)serialization failed.
    #[error("control codec error: {0}")]
    Codec(String),

    /// The signature field was not the expected 64 bytes.
    #[error("signature is malformed (expected 64 bytes, got {0})")]
    BadSignatureLen(usize),

    /// The Ed25519 signature did not verify against the operator key.
    ///
    /// The core boundary-A rejection: a control request the daemon cannot
    /// prove came from the trusted operator key is never acted on. (Peer
    /// credentials are also checked, at the socket layer, by the daemon.)
    #[error("operator signature verification failed")]
    SignatureInvalid,

    /// A length-prefixed frame was malformed or exceeded the size limit.
    #[error("framing error: {0}")]
    Framing(String),
}
