//! `.exec` format error types.

/// Errors produced while loading, verifying, or validating a `.exec` bundle.
///
/// Every variant is a *rejection*. There is no "soft failure": if loading a
/// bundle does not return [`Ok`], the bundle MUST NOT be executed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecFormatError {
    /// Bundle or signature file could not be read.
    #[error("I/O error reading bundle: {0}")]
    Io(#[from] std::io::Error),

    /// The detached signature is malformed (wrong length / not hex).
    #[error("malformed signature: {0}")]
    BadSignature(String),

    /// No trusted operator key produced a valid signature over the bundle.
    ///
    /// This is the layer #6 rejection: an unsigned or wrongly-signed bundle
    /// is never trusted.
    #[error("signature does not verify against any trusted operator key")]
    Untrusted,

    /// The operator trust file is malformed.
    #[error("invalid operator trust file: {0}")]
    BadTrustFile(String),

    /// The manifest is not valid TOML or violates the schema.
    #[error("invalid manifest: {0}")]
    BadManifest(String),

    /// The payload bytes do not match the SHA-256 declared in the manifest.
    #[error("payload hash mismatch: manifest declares {declared}, payload is {actual}")]
    PayloadHashMismatch {
        /// Hash the (signed) manifest declares.
        declared: String,
        /// Hash actually computed over the payload.
        actual: String,
    },

    /// A declared argument schema regex failed to compile.
    #[error("argument {arg:?} has an invalid regex: {source}")]
    BadArgRegex {
        /// The argument whose regex is invalid.
        arg: String,
        /// The underlying regex error.
        source: regex::Error,
    },

    /// Provided arguments failed schema validation (layer #7).
    #[error("argument validation failed: {0}")]
    ArgRejected(String),
}
