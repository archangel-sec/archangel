//! `.exec` bundle parser and signature verifier.
//!
//! Implements layers #6 and #7: signed action bundles with declared argument
//! schemas. Anything this crate accepts must have a valid Ed25519 signature
//! from a key listed in the operator trust chain.
//!
//! See `docs/EXEC_FORMAT.md` (to be written) for the on-disk format.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
