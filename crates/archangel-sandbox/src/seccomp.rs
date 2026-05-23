//! Named seccomp-bpf profiles → a compiled, fail-closed BPF program.
//!
//! Profiles are **defined in code, not data**: a bundle selects one by name
//! and cannot widen it. The compiled filter's mismatch action is
//! `KillProcess` — any syscall not on the profile's allowlist terminates the
//! action immediately. The allowlist is deliberately scoped to what a
//! read-only inspection (`bash` + common coreutils + `systemctl status` /
//! `journalctl` / `ps` / `df`) needs; escape and escalation syscalls
//! (network, mount, ptrace, module load, privilege change, filesystem
//! mutation) are *absent* and therefore killed. See `docs/SANDBOX.md`.
//!
//! Only `x86_64` and `aarch64` are supported (the v0.2 server targets). Any
//! other Linux arch is a hard build error rather than a silently
//! under-specified — and thus potentially over-permissive — filter.

use std::collections::BTreeMap;

use nix::libc;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

use crate::SandboxError;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "archangel-sandbox seccomp profiles are audited for x86_64 and aarch64 \
     only; refusing to build an unaudited syscall allowlist for this arch"
);

/// The seccomp target arch for the arch we are compiled for.
const fn target_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
}

/// `libc::SYS_*` are `c_long`; seccompiler keys on `i64`. On the 64-bit
/// arches we support this is an identity widening.
#[allow(clippy::cast_possible_truncation, clippy::unnecessary_cast)]
const fn n(syscall: libc::c_long) -> i64 {
    syscall as i64
}

/// Syscalls common to every supported arch (the modern, `*at` set glibc and
/// coreutils use). Kept sorted by rough category for review.
fn common_allow() -> Vec<i64> {
    vec![
        // --- I/O on already-open fds ---
        n(libc::SYS_read),
        n(libc::SYS_write),
        n(libc::SYS_readv),
        n(libc::SYS_writev),
        n(libc::SYS_pread64),
        n(libc::SYS_close),
        n(libc::SYS_lseek),
        n(libc::SYS_fcntl),
        n(libc::SYS_ioctl), // TCGETS probing; no tty ⇒ ENOTTY, but must not kill
        n(libc::SYS_dup),
        n(libc::SYS_dup3),
        n(libc::SYS_pipe2),
        // --- path lookup / metadata (read side) ---
        n(libc::SYS_openat),
        n(libc::SYS_newfstatat),
        n(libc::SYS_statx),
        n(libc::SYS_getdents64),
        n(libc::SYS_readlinkat),
        n(libc::SYS_faccessat),
        n(libc::SYS_getcwd),
        n(libc::SYS_chdir),
        // --- memory ---
        n(libc::SYS_brk),
        n(libc::SYS_mmap),
        n(libc::SYS_munmap),
        n(libc::SYS_mprotect),
        n(libc::SYS_mremap),
        n(libc::SYS_madvise),
        // --- signals ---
        n(libc::SYS_rt_sigaction),
        n(libc::SYS_rt_sigprocmask),
        n(libc::SYS_rt_sigreturn),
        n(libc::SYS_rt_sigtimedwait),
        n(libc::SYS_sigaltstack),
        n(libc::SYS_restart_syscall),
        // --- time / sleep ---
        n(libc::SYS_nanosleep),
        n(libc::SYS_clock_nanosleep),
        n(libc::SYS_clock_gettime),
        n(libc::SYS_clock_getres),
        n(libc::SYS_gettimeofday),
        // --- identity (read-only) ---
        n(libc::SYS_getpid),
        n(libc::SYS_getppid),
        n(libc::SYS_gettid),
        n(libc::SYS_getuid),
        n(libc::SYS_geteuid),
        n(libc::SYS_getgid),
        n(libc::SYS_getegid),
        n(libc::SYS_getgroups),
        n(libc::SYS_getpgid),
        n(libc::SYS_getsid),
        // bash pipeline/job-control sets the process group of the children
        // it forks; benign inside the sandbox (only own/child pgrp/session).
        n(libc::SYS_setpgid),
        n(libc::SYS_setsid),
        // Local-IPC socket *operations*. These are inert for networking:
        // `socket(2)` itself is allowed ONLY for AF_UNIX / AF_NETLINK (see
        // `socket_rules`), so an AF_INET/AF_INET6 socket can never be
        // created — and these ops therefore can never act on one. This is
        // the same posture as systemd's `RestrictAddressFamilies=AF_UNIX
        // AF_NETLINK`: restrict at creation, allow the ops. Needed by glibc
        // NSS (`getpwuid` via nss_systemd over an AF_UNIX socket) and
        // interface enumeration (`__check_pf` over AF_NETLINK).
        n(libc::SYS_connect),
        n(libc::SYS_bind),
        n(libc::SYS_socketpair),
        n(libc::SYS_sendto),
        n(libc::SYS_recvfrom),
        n(libc::SYS_sendmsg),
        n(libc::SYS_recvmsg),
        n(libc::SYS_getsockopt),
        n(libc::SYS_setsockopt),
        n(libc::SYS_getpeername),
        n(libc::SYS_getsockname),
        // --- thread/runtime setup ---
        n(libc::SYS_set_tid_address),
        n(libc::SYS_set_robust_list),
        n(libc::SYS_rseq),
        n(libc::SYS_prlimit64),
        n(libc::SYS_getrlimit),
        n(libc::SYS_futex),
        n(libc::SYS_sched_yield),
        n(libc::SYS_sched_getaffinity),
        // --- wait/poll ---
        n(libc::SYS_ppoll),
        n(libc::SYS_pselect6),
        n(libc::SYS_epoll_create1),
        n(libc::SYS_epoll_ctl),
        n(libc::SYS_epoll_pwait),
        // --- process lifecycle (bash spawns coreutils) ---
        n(libc::SYS_clone),
        n(libc::SYS_clone3),
        n(libc::SYS_execve),
        n(libc::SYS_execveat),
        n(libc::SYS_wait4),
        n(libc::SYS_waitid),
        n(libc::SYS_exit),
        n(libc::SYS_exit_group),
        n(libc::SYS_tgkill),
        n(libc::SYS_kill), // bash job control over its own children
        // --- read-only filesystem/system info (df, free, cat fadvise) ---
        n(libc::SYS_statfs),
        n(libc::SYS_fstatfs),
        n(libc::SYS_fadvise64),
        n(libc::SYS_uname),
        n(libc::SYS_sysinfo),
        n(libc::SYS_times),
        n(libc::SYS_getrandom),
        n(libc::SYS_membarrier),
        n(libc::SYS_umask),
        n(libc::SYS_prctl), // bash/glibc; no_new_privs is already latched
    ]
}

/// Syscalls that exist only on legacy/`x86_64` (aarch64 dropped the
/// non-`*at`, non-`p*` variants in favour of the modern ones above).
#[cfg(target_arch = "x86_64")]
fn arch_extra_allow() -> Vec<i64> {
    vec![
        n(libc::SYS_open),
        n(libc::SYS_stat),
        n(libc::SYS_lstat),
        n(libc::SYS_fstat),
        n(libc::SYS_poll),
        n(libc::SYS_select),
        n(libc::SYS_access),
        n(libc::SYS_dup2),
        n(libc::SYS_pipe),
        n(libc::SYS_fork),
        n(libc::SYS_vfork),
        n(libc::SYS_readlink),
        n(libc::SYS_arch_prctl),
        n(libc::SYS_epoll_create),
        n(libc::SYS_epoll_wait),
        n(libc::SYS_getpgrp),
        n(libc::SYS_time),
    ]
}

#[cfg(target_arch = "aarch64")]
fn arch_extra_allow() -> Vec<i64> {
    vec![n(libc::SYS_fstat)]
}

/// The known profile names. A bundle's `syscall_profile` must equal one of
/// these exactly; anything else is [`SandboxError::UnknownProfile`].
const KNOWN_PROFILES: &[&str] = &["inspect"];

/// Resolve a profile name to its concrete syscall allowlist. v0.2 ships
/// exactly one audited profile (`inspect`); a second profile is not added
/// until it can be end-to-end exercised, to avoid shipping an unverified
/// (and therefore potentially over-broad) filter.
fn allowlist_for(profile: &str) -> Result<Vec<i64>, SandboxError> {
    match profile {
        "inspect" => {
            let mut v = common_allow();
            v.extend(arch_extra_allow());
            Ok(v)
        }
        other => Err(SandboxError::UnknownProfile(other.to_owned())),
    }
}

/// `socket(2)` is allowed only for local-IPC address families. Two OR-ed
/// rules: `domain == AF_UNIX` or `domain == AF_NETLINK`. Any other family
/// (notably `AF_INET`/`AF_INET6`) matches neither rule and so hits the
/// kill-on-mismatch default — no network socket can ever be created.
fn socket_rules() -> Result<Vec<SeccompRule>, SandboxError> {
    let compile = |e: seccompiler::BackendError| {
        SandboxError::SeccompCompile(e.to_string())
    };
    let family = |af: libc::c_int| -> Result<SeccompRule, SandboxError> {
        // arg0 of socket(2) is `domain`, a 32-bit int.
        #[allow(clippy::cast_sign_loss)]
        let cond = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            af as u64,
        )
        .map_err(compile)?;
        SeccompRule::new(vec![cond]).map_err(compile)
    };
    Ok(vec![family(libc::AF_UNIX)?, family(libc::AF_NETLINK)?])
}

/// The full rule map for a profile: every unconditional syscall mapped to an
/// empty rule chain (allow), plus the argument-conditioned `socket` entry.
fn rules_for(
    profile: &str,
) -> Result<BTreeMap<i64, Vec<SeccompRule>>, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = allowlist_for(profile)?
        .into_iter()
        .map(|s| (s, Vec::new()))
        .collect();
    rules.insert(n(libc::SYS_socket), socket_rules()?);
    Ok(rules)
}

/// A named profile resolved to a compiled BPF program, ready to install on
/// the action thread just before `execve`.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    name: String,
    program: BpfProgram,
}

impl SeccompProfile {
    /// Compile `profile` into a kill-on-mismatch BPF program.
    ///
    /// # Errors
    /// - [`SandboxError::UnknownProfile`] if the name is not recognized
    ///   (fail-closed: never resolved to a permissive filter).
    /// - [`SandboxError::SeccompCompile`] if the allowlist cannot be lowered
    ///   to BPF (should not happen for the in-code profiles; still surfaced
    ///   rather than panicked).
    pub fn compile(profile: &str) -> Result<Self, SandboxError> {
        let rules = rules_for(profile)?;

        let filter = SeccompFilter::new(
            rules,
            // Mismatch ⇒ a syscall outside the allowlist ⇒ kill the whole
            // action process. Not `Errno`: a steered payload must not get a
            // chance to observe-and-adapt; it dies.
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            target_arch(),
        )
        .map_err(|e| SandboxError::SeccompCompile(e.to_string()))?;

        let program = BpfProgram::try_from(filter)
            .map_err(|e| SandboxError::SeccompCompile(e.to_string()))?;

        Ok(Self {
            name: profile.to_owned(),
            program,
        })
    }

    /// The profile name (for audit / diagnostics).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The compiled BPF program (installed by the audited applier).
    #[must_use]
    pub const fn program(&self) -> &BpfProgram {
        &self.program
    }

    /// The set of profile names this build recognizes. A bundle's
    /// `syscall_profile` must equal one of these exactly.
    #[must_use]
    pub const fn known() -> &'static [&'static str] {
        KNOWN_PROFILES
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{allowlist_for, SeccompProfile};
    use crate::SandboxError;
    use nix::libc;

    #[test]
    fn every_known_profile_compiles() {
        for p in SeccompProfile::known() {
            let prof = SeccompProfile::compile(p)
                .unwrap_or_else(|e| panic!("profile {p} must compile: {e}"));
            assert_eq!(prof.name(), *p);
            assert!(
                !prof.program().is_empty(),
                "compiled BPF program must be non-empty"
            );
        }
    }

    #[test]
    fn unknown_profile_is_rejected_not_permissive() {
        let err = SeccompProfile::compile("totally-made-up").unwrap_err();
        assert_eq!(
            err,
            SandboxError::UnknownProfile("totally-made-up".to_owned())
        );
    }

    #[test]
    fn empty_profile_name_is_rejected() {
        assert!(matches!(
            SeccompProfile::compile(""),
            Err(SandboxError::UnknownProfile(_))
        ));
    }

    #[test]
    fn inspect_allows_core_io_and_process_syscalls() {
        let allow = allowlist_for("inspect").expect("inspect resolves");
        for required in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_exit_group,
        ] {
            assert!(
                allow.contains(&required),
                "inspect must allow syscall {required}"
            );
        }
    }

    #[test]
    fn inspect_denies_escape_and_escalation_syscalls() {
        let allow = allowlist_for("inspect").expect("inspect resolves");
        // The whole point of layer #11: these must NOT be on the list, so
        // the kill-on-mismatch default terminates any attempt.
        for forbidden in [
            libc::SYS_mount,
            libc::SYS_ptrace,
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_unlinkat,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_kexec_load,
            libc::SYS_bpf,
            libc::SYS_ptrace,
            libc::SYS_listen,
            libc::SYS_accept,
        ] {
            assert!(
                !allow.contains(&forbidden),
                "inspect must NOT allow dangerous syscall {forbidden}"
            );
        }
    }

    #[test]
    fn socket_is_present_only_as_a_conditioned_rule() {
        // `socket` is NOT an unconditional allow…
        let allow = allowlist_for("inspect").expect("inspect resolves");
        assert!(!allow.contains(&libc::SYS_socket));
        // …but the compiled rule map carries it with non-empty (i.e.
        // argument-conditioned) rules restricting the address family.
        let rules = super::rules_for("inspect").expect("rules build");
        let socket_rules = rules
            .get(&libc::SYS_socket)
            .expect("socket entry present");
        assert_eq!(
            socket_rules.len(),
            2,
            "expected AF_UNIX and AF_NETLINK rules"
        );
    }

    #[test]
    fn allowlist_has_no_duplicates() {
        let mut allow = allowlist_for("inspect").expect("inspect resolves");
        let before = allow.len();
        allow.sort_unstable();
        allow.dedup();
        assert_eq!(before, allow.len(), "duplicate syscall in allowlist");
    }
}
