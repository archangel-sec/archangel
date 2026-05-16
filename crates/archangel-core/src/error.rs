//! Core error types.

/// Errors produced by archangel-core primitives.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// An identifier string was malformed or had the wrong length.
    #[error("invalid identifier: {0}")]
    InvalidId(String),
}
