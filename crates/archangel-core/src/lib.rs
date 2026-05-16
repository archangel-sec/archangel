//! Shared primitives for the archangel project.
//!
//! This crate is intentionally tiny. It contains the types and error categories
//! that flow across every other crate, plus zeroize-aware wrappers for secret
//! material. It performs no I/O and has no global state.
//!
//! See `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md` for context.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
