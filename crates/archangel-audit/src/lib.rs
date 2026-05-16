//! Hash-chained, signed audit log.
//!
//! Implements layer #15 of the threat model. Every entry is signed with the
//! daemon's audit key and includes the SHA-256 of the previous entry, forming
//! a Merkle chain that makes tampering with the past detectable.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
