//! Shared primitives for the archangel project.
//!
//! This crate is intentionally minimal. It provides the types and error
//! categories shared across every other archangel crate, plus zeroize-aware
//! wrappers for secret material. It performs no I/O and holds no global state.
//!
//! See `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md` for the design
//! rationale behind each type.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Core error types.
pub mod error;
/// Typed 128-bit identifiers for sessions and actions.
pub mod id;
/// Operation modes and risk classifications.
pub mod mode;
/// Zeroize-aware wrappers for secret material.
pub mod secret;

pub use error::CoreError;
pub use id::{ActionId, SessionId};
pub use mode::{OperationMode, RiskLevel};
pub use secret::{SecretBytes, SecretString};
