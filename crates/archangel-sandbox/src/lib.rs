//! Per-action sandbox construction.
//!
//! Implements layer #11 of the threat model: every action runs in an
//! ephemeral container composed of Linux namespaces, a seccomp-bpf allowlist,
//! a minimal capability set, and cgroup v2 resource limits.
//!
//! This is the crate most likely to require small amounts of `unsafe` for
//! raw syscalls. Any `unsafe` block here MUST carry a `// SAFETY:` justification
//! and is gated by CODEOWNERS review.

#![cfg_attr(target_os = "linux", forbid(unsafe_code))]
// Non-Linux targets compile to stubs that explicitly do nothing.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![warn(missing_docs)]
