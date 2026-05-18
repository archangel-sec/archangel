//! Sandbox subsystem errors.

/// Why a sandbox plan could not be built (or applied).
///
/// Every variant is fail-closed at the call site: an action whose sandbox
/// plan cannot be constructed MUST NOT run. There is deliberately no
/// "fallback to weaker isolation" path — a missing or invalid constraint is
/// a refusal, never a downgrade.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxError {
    /// The bundle named a seccomp profile this build does not define. The
    /// set of profiles is fixed in code; an unknown name is rejected rather
    /// than resolved to a permissive filter.
    #[error("unknown seccomp profile {0:?}")]
    UnknownProfile(String),

    /// The bundle requested a capability string that is not a recognized
    /// Linux capability. Rejected rather than silently dropped.
    #[error("unknown capability {0:?}")]
    UnknownCapability(String),

    /// A resource limit (`cpu_max` / `memory_max`) was syntactically or
    /// semantically invalid. Never interpreted as "unlimited".
    #[error("invalid resource limit: {0}")]
    InvalidLimit(String),

    /// The declarative profile was internally inconsistent (e.g. a path
    /// escaping its allowed root, an empty profile name).
    #[error("invalid sandbox profile: {0}")]
    InvalidProfile(String),

    /// Compiling the seccomp allowlist into a BPF program failed.
    #[error("seccomp compilation failed: {0}")]
    SeccompCompile(String),

    /// The sandbox is not available on this platform/build (non-Linux). The
    /// caller must refuse the action — there is no isolation to apply.
    #[error("sandbox unsupported on this platform")]
    Unsupported,
}
