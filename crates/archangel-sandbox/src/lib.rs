//! Per-action sandbox construction — threat-model **layer #11**.
//!
//! Every action runs in an ephemeral, locked-down container: a seccomp-bpf
//! syscall allowlist, a capability set dropped to the bundle's explicit list,
//! Linux namespaces, and cgroup v2 resource limits. See `docs/SANDBOX.md` for
//! the full model and the `unsafe` discipline.
//!
//! # Structure
//!
//! Everything here is ordinary, fully-tested safe Rust: it *decides* what the
//! sandbox will be ([`SandboxPlan`]) from the verified bundle's declarative
//! profile. The single audited `unsafe` step that *applies* the plan in the
//! post-fork / pre-exec hook is staged separately (see `docs/SANDBOX.md` §5)
//! so all security-relevant logic stays testable without root or `unsafe`.
//!
//! # Fail-closed
//!
//! Construction is total. An unknown seccomp profile, an unknown capability,
//! or an unparseable resource limit yields **no plan** — never a permissive
//! one. The executor refuses any action it cannot build a plan for: no
//! sandbox, no execution.
//!
//! # `unsafe`
//!
//! This crate uses `#![deny(unsafe_code)]` (not `forbid`) so exactly one
//! reviewed, `// SAFETY:`-justified block may exist. Its lint table is
//! written out in `Cargo.toml` rather than inherited, and the crate is
//! CODEOWNERS-gated. No `unsafe` exists in this unit.

#![deny(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![warn(missing_docs)]

mod error;

pub use error::SandboxError;

#[cfg(target_os = "linux")]
mod apply;
#[cfg(target_os = "linux")]
mod capability;
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod plan;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
pub use cgroup::Cgroup;
#[cfg(target_os = "linux")]
pub use plan::{NetworkMode, SandboxPlan, SandboxPolicy};

/// Non-Linux stub. The sandbox is Linux-only; on other platforms the crate
/// builds so the workspace checks from a developer laptop, but a plan can
/// never be produced — every attempt is `Unsupported` (fail-closed, so a
/// non-Linux build can structurally never *run* an unsandboxed action).
#[cfg(not(target_os = "linux"))]
mod plan {
    use crate::SandboxError;

    /// Stub policy (non-Linux): carries nothing; cannot be planned.
    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    pub struct SandboxPolicy;

    /// Stub plan (non-Linux): never constructed.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum SandboxPlan {}

    impl SandboxPolicy {
        /// Always fails on non-Linux: there is no sandbox to build.
        ///
        /// # Errors
        /// Always [`SandboxError::Unsupported`].
        pub fn plan(&self) -> Result<SandboxPlan, SandboxError> {
            Err(SandboxError::Unsupported)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use plan::{SandboxPlan, SandboxPolicy};
