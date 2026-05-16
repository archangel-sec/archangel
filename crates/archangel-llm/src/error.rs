//! LLM backend error types.

/// Errors produced by an LLM backend.
///
/// Error values are deliberately terse and never embed the API key, the
/// full prompt, or the full response. Rich audit logging of prompts and
/// responses is `archangeld`'s responsibility (the signed audit log), not
/// the transport's — keeping secrets out of error paths reduces the chance
/// of leaking them into ordinary logs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LlmError {
    /// The backend was configured with an unusable value (bad URL, an
    /// `http://` endpoint where TLS is required, etc.). Detected before
    /// any network I/O.
    #[error("invalid backend configuration: {0}")]
    InvalidConfig(String),

    /// The HTTP transport failed (DNS, connect, TLS, timeout).
    #[error("transport error: {0}")]
    Transport(String),

    /// The endpoint returned a non-success status.
    #[error("backend returned HTTP {status}: {snippet}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// A short, truncated snippet of the body for diagnostics.
        snippet: String,
    },

    /// The response body exceeded the configured size cap. Treated as
    /// hostile: a compromised or buggy endpoint must not be able to OOM
    /// the daemon.
    #[error("response exceeded the {max_bytes}-byte cap")]
    ResponseTooLarge {
        /// The configured maximum.
        max_bytes: usize,
    },

    /// The response could not be decoded into the expected shape.
    #[error("could not decode backend response: {0}")]
    Decode(String),
}
