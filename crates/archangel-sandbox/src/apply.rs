//! The **single audited `unsafe` site** of the entire project.
//!
//! Everything that *decides* the sandbox is safe, tested code (see
//! [`crate::SandboxPlan`]). This module only *enacts* an already-validated
//! plan in the forked child immediately before `execve`, via
//! [`std::os::unix::process::CommandExt::pre_exec`].
//!
//! `pre_exec` is an `unsafe fn` because its closure runs after `fork(2)` in
//! a process that shares the parent's address space but only the calling
//! thread: the closure must do **only async-signal-safe work** and must not
//! touch data guarded by locks that another (now-absent) thread could have
//! held. We honour that by doing exactly two raw syscalls, no allocation,
//! no locking, on the success path — and failing closed (the child returns
//! an error, so `execve` never happens and the action does not run).
//!
//! v0.2 scope (see `docs/SANDBOX.md` §4–5): this installs `no_new_privs`
//! and the compiled seccomp filter — the substantive layer-#11 guarantee
//! (a forbidden syscall *kills the process*; network/mount/ptrace/module/
//! privilege-change/fs-mutation syscalls are absent from the `inspect`
//! allowlist and therefore fatal). Namespace unshare, the user-namespace
//! uid map, mount binding, and parent-side cgroup attach are deferred to
//! the following unit and are explicitly *not* silently skipped: the
//! enforced syscall surface already denies the escape vectors they would
//! also block.

use std::{io, os::unix::process::CommandExt as _, process::Command};

use seccompiler::BpfProgram;

use crate::SandboxPlan;

impl SandboxPlan {
    /// Arm `cmd` so that, in the forked child and just before `execve`, the
    /// process latches `no_new_privs` and installs this plan's seccomp
    /// filter. After arming, a syscall outside the profile's allowlist
    /// terminates the child (fail-closed).
    ///
    /// The seccomp program is cloned out of the plan *before* the fork so
    /// the child-side closure performs no allocation on the success path.
    pub fn harden(&self, cmd: &mut Command) {
        let program: BpfProgram = self.seccomp().program().clone();

        // SAFETY: the closure runs post-`fork`, pre-`execve`, in the child,
        // on the calling thread only. Async-signal-safety requirements:
        //  - It performs no heap allocation, takes no lock, and touches no
        //    shared mutable state on the success path. `program` is a
        //    `Vec<sock_filter>` fully built and moved into the closure
        //    before the fork; we only borrow it as a slice here.
        //  - `prctl(PR_SET_NO_NEW_PRIVS)` and the `seccomp(2)` performed by
        //    `seccompiler::apply_filter` are each a single syscall, which is
        //    async-signal-safe. `set_no_new_privs` must precede the filter:
        //    an unprivileged process cannot install a seccomp filter unless
        //    no-new-privs is set.
        //  - On error we return `Err`; the std runtime then makes the child
        //    exit without `execve`, so the action never runs (fail-closed).
        //    The only allocation (`io::Error::other`) is on that dying-child
        //    error path and is the accepted convention for `pre_exec`.
        //  - The closure is `FnMut` but holds no state mutated across calls;
        //    `std` invokes it once per spawn.
        //
        // This is the project's sole `unsafe`. `deny` (not `forbid`) +
        // CODEOWNERS exists precisely so this one reviewed site can opt in.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || install(&program));
        }
    }
}

/// The child-side application: latch no-new-privs, then load the BPF filter.
/// Two syscalls, in this exact order; any failure is fatal to the child.
fn install(program: &BpfProgram) -> io::Result<()> {
    nix::sys::prctl::set_no_new_privs()
        .map_err(|e| io::Error::other(format!("set_no_new_privs: {e}")))?;
    seccompiler::apply_filter(program.as_slice())
        .map_err(|e| io::Error::other(format!("seccomp apply: {e}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::process::Command;

    use nix::libc;

    use crate::SandboxPolicy;

    fn inspect_plan() -> crate::SandboxPlan {
        SandboxPolicy {
            syscall_profile: "inspect".to_owned(),
            ..SandboxPolicy::default()
        }
        .plan()
        .expect("inspect plan builds")
    }

    /// A hardened `true` must still run (the allowlist covers a trivial
    /// process: `execve`, `brk`/`mmap`, `exit_group`, …). This is the
    /// golden path — if it fails the `inspect` profile is too tight.
    #[test]
    fn hardened_trivial_process_succeeds() {
        let mut cmd = Command::new("true");
        inspect_plan().harden(&mut cmd);
        let status = cmd.status().expect("spawn true");
        assert!(
            status.success(),
            "hardened `true` should exit 0, got {status:?}"
        );
    }

    /// A hardened process that issues a syscall *not* on the `inspect`
    /// allowlist must be killed, not allowed to proceed. `unshare(2)` is a
    /// deliberate escape syscall and is absent from the profile.
    #[test]
    fn hardened_process_is_killed_on_forbidden_syscall() {
        // `unshare --map-root-user true` calls unshare(2); the kernel
        // SIGKILLs the process the moment it does. We assert it did not
        // exit successfully (it is terminated, not merely erroring).
        let mut cmd = Command::new("unshare");
        cmd.arg("--map-root-user").arg("true");
        inspect_plan().harden(&mut cmd);
        // If `unshare` is not installed, spawn fails before the filter can
        // prove anything ⇒ skip. Otherwise it must NOT exit successfully.
        if let Ok(status) = cmd.status() {
            assert!(
                !status.success(),
                "forbidden syscall must not yield success: {status:?}"
            );
        }
    }

    /// A hardened bash running a read-only inspection still works end to
    /// end (echo + coreutils-style pipeline), proving the profile is usable
    /// for the v0.1/v0.2 read-only workload.
    #[test]
    fn hardened_bash_readonly_pipeline_works() {
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg("echo hello | cat; exit 0");
        inspect_plan().harden(&mut cmd);
        let out = cmd.output().expect("spawn bash");
        assert!(out.status.success(), "stderr: {:?}", out.stderr);
        assert_eq!(out.stdout, b"hello\n");
    }

    /// bash startup must survive even with a *cleared* environment — that
    /// path drives glibc NSS (`getpwuid` via `nss_systemd` over an
    /// `AF_UNIX` socket) and interface enumeration (`AF_NETLINK`), which the
    /// profile permits. This mirrors how the executor actually spawns
    /// actions.
    #[test]
    fn hardened_bash_with_cleared_env_survives_nss() {
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg("exit 0")
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        inspect_plan().harden(&mut cmd);
        let status = cmd.status().expect("spawn bash");
        assert!(
            status.success(),
            "bash with cleared env (NSS path) must survive: {status:?}"
        );
    }

    /// Creating an `AF_INET` socket — the prerequisite for any network
    /// egress — must be fatal, proving the address-family restriction holds
    /// at runtime even though local-IPC socket ops are permitted. bash's
    /// `/dev/tcp` redirection issues `socket(AF_INET, …)`.
    #[test]
    fn hardened_inet_socket_is_killed() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg("exec 3<>/dev/tcp/127.0.0.1/9")
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        inspect_plan().harden(&mut cmd);
        let status = cmd.status().expect("spawn bash");
        assert_eq!(
            status.signal(),
            Some(libc::SIGSYS),
            "AF_INET socket must trigger the seccomp kill (SIGSYS), got {status:?}"
        );
    }
}
