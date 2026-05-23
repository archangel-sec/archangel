//! [`SandboxPolicy`] (decoupled input) → a validated [`SandboxPlan`].
//!
//! The executor maps the *verified* bundle's `[sandbox]` manifest section
//! onto a [`SandboxPolicy`] (this crate does not depend on the manifest
//! parser, so the enforcement core stays independently testable). Calling
//! [`SandboxPolicy::plan`] runs every fail-closed check; the resulting
//! [`SandboxPlan`] is the complete, validated description the single audited
//! `unsafe` applier will enact. If a plan cannot be built the executor
//! refuses the action: no sandbox, no execution.

use crate::{
    capability::CapabilitySet,
    cgroup::{CpuMax, MemoryMax},
    seccomp::SeccompProfile,
    SandboxError,
};

/// Network posture for the action, decoupled from the manifest's enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// No network at all: a fresh, empty network namespace (default-safe).
    #[default]
    None,
    /// Loopback only: a fresh network namespace with `lo` up.
    Loopback,
    /// Egress permitted, still subject to the kernel egress filter (#17).
    Egress,
}

/// Which namespaces the applier will unshare. `user` is *requested* here but
/// whether it can actually be created is decided at apply time (it may be
/// unavailable); the rest are mandatory for the sandbox to mean anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// A deliberate flag set: one bool per Linux namespace kind. Folding these
// into an enum/bitflags would obscure, not clarify, the per-namespace intent.
#[allow(clippy::struct_excessive_bools)]
pub struct Namespaces {
    /// Mount namespace (mandatory: isolates the filesystem view).
    pub mount: bool,
    /// PID namespace (mandatory: cannot see/signal host processes).
    pub pid: bool,
    /// IPC namespace (mandatory: no shared SysV/POSIX IPC with the host).
    pub ipc: bool,
    /// UTS namespace (mandatory: hostname isolation).
    pub uts: bool,
    /// cgroup namespace (mandatory: hides the host cgroup tree).
    pub cgroup: bool,
    /// User namespace (requested; applier degrades fail-closed if it cannot
    /// be created — it never proceeds *without* the other isolations).
    pub user: bool,
    /// Network namespace (a fresh, isolated one unless egress is permitted).
    pub net: bool,
}

/// The declarative sandbox request, mapped from the verified manifest by the
/// executor. Decoupled from `archangel-exec-format` on purpose.
#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    /// Named seccomp profile to compile.
    pub syscall_profile: String,
    /// Capability names to retain (default: none).
    pub capabilities: Vec<String>,
    /// Paths to expose read-only inside the mount namespace.
    pub allowed_paths_ro: Vec<String>,
    /// Paths to expose read-write inside the mount namespace.
    pub allowed_paths_rw: Vec<String>,
    /// Network posture.
    pub network: NetworkMode,
    /// Optional CPU ceiling string (e.g. `"10%"`).
    pub cpu_max: Option<String>,
    /// Optional memory ceiling string (e.g. `"128M"`).
    pub memory_max: Option<String>,
}

/// A fully-validated, ready-to-apply sandbox description.
///
/// Construction (via [`SandboxPolicy::plan`]) is the only way to obtain one
/// and it performs every fail-closed check, so a `SandboxPlan` *in hand* is
/// proof the request was acceptable.
#[derive(Debug, Clone)]
pub struct SandboxPlan {
    seccomp: SeccompProfile,
    capabilities: CapabilitySet,
    cpu_max: Option<CpuMax>,
    memory_max: Option<MemoryMax>,
    paths_ro: Vec<String>,
    paths_rw: Vec<String>,
    network: NetworkMode,
    namespaces: Namespaces,
}

/// Reject anything that is not a clean, absolute path. A bundle is signed,
/// but layer #11 still does not trust the path it declares: traversal,
/// relative paths, NUL, and empty components are refused.
fn validate_path(p: &str) -> Result<(), SandboxError> {
    let bad = |m: &str| Err(SandboxError::InvalidProfile(format!("path {p:?}: {m}")));
    if p.is_empty() {
        return bad("empty");
    }
    if !p.starts_with('/') {
        return bad("must be absolute");
    }
    if p.len() > 4096 {
        return bad("too long");
    }
    if p.contains('\0') {
        return bad("contains NUL");
    }
    if p.split('/').any(|c| c == "..") {
        return bad("contains a `..` component");
    }
    Ok(())
}

impl SandboxPolicy {
    /// Validate this policy and resolve it into a [`SandboxPlan`].
    ///
    /// # Errors
    /// Fail-closed; the first failing check wins:
    /// - [`SandboxError::UnknownProfile`] — unrecognized seccomp profile.
    /// - [`SandboxError::UnknownCapability`] — unrecognized capability.
    /// - [`SandboxError::InvalidLimit`] — unparseable `cpu_max`/`memory_max`.
    /// - [`SandboxError::InvalidProfile`] — a bad declared path.
    /// - [`SandboxError::SeccompCompile`] — BPF lowering failed.
    pub fn plan(&self) -> Result<SandboxPlan, SandboxError> {
        let seccomp = SeccompProfile::compile(&self.syscall_profile)?;
        let capabilities = CapabilitySet::resolve(&self.capabilities)?;

        let cpu_max = match &self.cpu_max {
            Some(s) => Some(CpuMax::parse(s)?),
            None => None,
        };
        let memory_max = match &self.memory_max {
            Some(s) => Some(MemoryMax::parse(s)?),
            None => None,
        };

        for p in self.allowed_paths_ro.iter().chain(&self.allowed_paths_rw) {
            validate_path(p)?;
        }

        // Mandatory isolations are always on. `net` is a fresh, isolated
        // namespace unless egress is explicitly permitted (in which case
        // host networking is reached but constrained by the egress filter
        // #17 at apply time).
        let namespaces = Namespaces {
            mount: true,
            pid: true,
            ipc: true,
            uts: true,
            cgroup: true,
            user: true,
            net: !matches!(self.network, NetworkMode::Egress),
        };

        Ok(SandboxPlan {
            seccomp,
            capabilities,
            cpu_max,
            memory_max,
            paths_ro: self.allowed_paths_ro.clone(),
            paths_rw: self.allowed_paths_rw.clone(),
            network: self.network,
            namespaces,
        })
    }
}

impl SandboxPlan {
    /// The compiled seccomp profile to install.
    #[must_use]
    pub const fn seccomp(&self) -> &SeccompProfile {
        &self.seccomp
    }

    /// The capability set to retain (all others dropped).
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    /// The validated CPU ceiling, if the bundle declared one.
    #[must_use]
    pub const fn cpu_max(&self) -> Option<CpuMax> {
        self.cpu_max
    }

    /// The validated memory ceiling, if the bundle declared one.
    #[must_use]
    pub const fn memory_max(&self) -> Option<MemoryMax> {
        self.memory_max
    }

    /// Paths to expose read-only in the mount namespace.
    #[must_use]
    pub fn paths_ro(&self) -> &[String] {
        &self.paths_ro
    }

    /// Paths to expose read-write in the mount namespace.
    #[must_use]
    pub fn paths_rw(&self) -> &[String] {
        &self.paths_rw
    }

    /// The resolved network posture.
    #[must_use]
    pub const fn network(&self) -> NetworkMode {
        self.network
    }

    /// The namespaces the applier must unshare.
    #[must_use]
    pub const fn namespaces(&self) -> Namespaces {
        self.namespaces
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{NetworkMode, SandboxPolicy};
    use crate::SandboxError;

    fn base() -> SandboxPolicy {
        SandboxPolicy {
            syscall_profile: "inspect".to_owned(),
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn minimal_valid_policy_plans() {
        let plan = base().plan().expect("minimal policy is valid");
        assert!(plan.capabilities().is_empty());
        assert!(plan.cpu_max().is_none());
        assert!(plan.memory_max().is_none());
        let ns = plan.namespaces();
        assert!(ns.mount && ns.pid && ns.ipc && ns.uts && ns.cgroup && ns.user);
        assert!(ns.net, "default (no network) ⇒ isolated net namespace");
        assert_eq!(plan.seccomp().name(), "inspect");
    }

    #[test]
    fn egress_keeps_host_net_namespace() {
        let p = SandboxPolicy {
            network: NetworkMode::Egress,
            ..base()
        };
        assert!(
            !p.plan().unwrap().namespaces().net,
            "egress ⇒ no fresh net namespace (host net, egress-filtered)"
        );
    }

    #[test]
    fn loopback_still_isolates_net() {
        let p = SandboxPolicy {
            network: NetworkMode::Loopback,
            ..base()
        };
        assert!(p.plan().unwrap().namespaces().net);
    }

    #[test]
    fn unknown_profile_fails_closed() {
        let p = SandboxPolicy {
            syscall_profile: "nope".to_owned(),
            ..base()
        };
        assert!(matches!(p.plan(), Err(SandboxError::UnknownProfile(_))));
    }

    #[test]
    fn unknown_capability_fails_closed() {
        let p = SandboxPolicy {
            capabilities: vec!["CAP_NOPE".to_owned()],
            ..base()
        };
        assert!(matches!(p.plan(), Err(SandboxError::UnknownCapability(_))));
    }

    #[test]
    fn bad_limits_fail_closed() {
        let cpu = SandboxPolicy {
            cpu_max: Some("nonsense".to_owned()),
            ..base()
        };
        assert!(matches!(cpu.plan(), Err(SandboxError::InvalidLimit(_))));
        let mem = SandboxPolicy {
            memory_max: Some("0".to_owned()),
            ..base()
        };
        assert!(matches!(mem.plan(), Err(SandboxError::InvalidLimit(_))));
    }

    #[test]
    fn valid_limits_resolve() {
        let p = SandboxPolicy {
            cpu_max: Some("10%".to_owned()),
            memory_max: Some("128M".to_owned()),
            ..base()
        };
        let plan = p.plan().expect("valid limits");
        assert_eq!(plan.cpu_max().unwrap().cgroup_value(), "10000 100000");
        assert_eq!(plan.memory_max().unwrap().bytes(), 128 * 1024 * 1024);
    }

    #[test]
    fn path_traversal_is_refused() {
        for bad in ["../etc", "relative/path", "", "/ok/../../escape"] {
            let p = SandboxPolicy {
                allowed_paths_ro: vec![bad.to_owned()],
                ..base()
            };
            assert!(
                matches!(p.plan(), Err(SandboxError::InvalidProfile(_))),
                "path {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn nul_in_path_is_refused() {
        let p = SandboxPolicy {
            allowed_paths_rw: vec!["/var/lib/\0evil".to_owned()],
            ..base()
        };
        assert!(matches!(p.plan(), Err(SandboxError::InvalidProfile(_))));
    }

    #[test]
    fn clean_absolute_paths_are_accepted() {
        let p = SandboxPolicy {
            allowed_paths_ro: vec!["/etc/archangel".to_owned()],
            allowed_paths_rw: vec!["/var/lib/archangel-exec".to_owned()],
            ..base()
        };
        let plan = p.plan().expect("clean paths accepted");
        assert_eq!(plan.paths_ro(), ["/etc/archangel"]);
        assert_eq!(plan.paths_rw(), ["/var/lib/archangel-exec"]);
    }
}
