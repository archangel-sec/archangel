//! Policy engine for archangel.
//!
//! Layers implemented here:
//! - #8: immutable denylist compiled into the binary.
//! - #9: signed allowlist + WASM policy evaluation.
//!
//! Both must agree before any action proceeds. The denylist is authoritative;
//! a deny here is final and cannot be overridden by allowlist or WASM policy.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod denylist;
