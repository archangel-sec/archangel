//! Minimal v0.1 process sandbox.
//!
//! # Honest scope
//!
//! This is **NOT** the real isolation layer. Threat model layer #11
//! (namespaces + seccomp-bpf + capabilities + cgroups v2) lands in v0.2 as
//! the `archangel-sandbox` crate. What this provides is process-level
//! hardening only:
//!
//! - a clean environment (no inherited env; minimal `PATH`, scoped `HOME`),
//! - no stdin,
//! - a fresh working directory,
//! - a hard wall-clock timeout (a hung action is killed, never wedges the
//!   executor),
//! - stdout/stderr captured under a byte cap (a chatty/hostile action
//!   cannot exhaust executor memory).
//!
//! Because v0.1 only ever runs `read_only = true` bundles, the blast radius
//! of this weaker sandbox is bounded by construction. We state the limit
//! plainly rather than imply isolation we do not yet have.

use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Inputs for one sandboxed run.
pub struct RunContext<'a> {
    /// The bash script (already authenticated via the signed bundle).
    pub script: &'a str,
    /// Validated argument values, exposed as `ARG_<name>` env vars.
    pub args: &'a BTreeMap<String, String>,
    /// Hard wall-clock timeout.
    pub timeout: Duration,
    /// Per-stream output cap in bytes.
    pub max_output: usize,
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// Exit code, or `-1` if killed (timeout/signal).
    pub exit_code: i32,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Captured stdout (UTF-8 lossy, capped).
    pub stdout: String,
    /// Captured stderr (UTF-8 lossy, capped).
    pub stderr: String,
    /// Whether either stream was truncated at `max_output`.
    pub truncated: bool,
}

/// Abstraction over "run this action". Injectable so the security pipeline
/// in [`crate::handler`] is unit-tested deterministically without spawning
/// real processes.
pub trait ActionRunner: Send + Sync {
    /// Execute and return the captured result. Implementations must honor
    /// the timeout and the output cap.
    fn run(&self, ctx: &RunContext<'_>) -> RunResult;
}

/// Read up to `cap` bytes from `reader`; report whether it was truncated.
fn read_capped<R: std::io::Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let take = chunk.get(..n).unwrap_or(&[]);
                if buf.len().saturating_add(take.len()) > cap {
                    let room = cap.saturating_sub(buf.len());
                    buf.extend_from_slice(take.get(..room).unwrap_or(&[]));
                    truncated = true;
                    // Keep draining so the child does not block on a full
                    // pipe, but discard the excess.
                    continue;
                }
                buf.extend_from_slice(take);
            }
        }
    }
    (buf, truncated)
}

/// The real runner: a hardened `bash` child process.
pub struct BashRunner;

impl ActionRunner for BashRunner {
    fn run(&self, ctx: &RunContext<'_>) -> RunResult {
        let started = Instant::now();

        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg(ctx.script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("LC_ALL", "C");
        for (k, v) in ctx.args {
            cmd.env(format!("ARG_{k}"), v);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return RunResult {
                    exit_code: -1,
                    duration_ms: dur_ms(started),
                    stdout: String::new(),
                    stderr: format!("spawn failed: {e}"),
                    truncated: false,
                }
            }
        };

        let cap = ctx.max_output;
        let out_pipe = child.stdout.take();
        let err_pipe = child.stderr.take();
        let out_handle =
            thread::spawn(move || out_pipe.map(|p| read_capped(p, cap)));
        let err_handle =
            thread::spawn(move || err_pipe.map(|p| read_capped(p, cap)));

        // Poll try_wait until the deadline; kill on timeout.
        let deadline = started + ctx.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(_) => break None,
            }
        };

        let (stdout, t1) = out_handle
            .join()
            .ok()
            .flatten()
            .unwrap_or_else(|| (Vec::new(), false));
        let (stderr, t2) = err_handle
            .join()
            .ok()
            .flatten()
            .unwrap_or_else(|| (Vec::new(), false));

        let exit_code = status
            .and_then(|s| s.code())
            .unwrap_or(-1);

        RunResult {
            exit_code,
            duration_ms: dur_ms(started),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            truncated: t1 || t2,
        }
    }
}

fn dur_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use super::{ActionRunner, BashRunner, RunContext};

    fn ctx<'a>(
        script: &'a str,
        args: &'a BTreeMap<String, String>,
        secs: u64,
    ) -> RunContext<'a> {
        RunContext {
            script,
            args,
            timeout: Duration::from_secs(secs),
            max_output: 64 * 1024,
        }
    }

    #[test]
    fn runs_and_captures_output() {
        let args = BTreeMap::new();
        let r = BashRunner.run(&ctx("echo hello; echo oops 1>&2", &args, 5));
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hello"));
        assert!(r.stderr.contains("oops"));
        assert!(!r.truncated);
    }

    #[test]
    fn args_are_exposed_as_env() {
        let mut args = BTreeMap::new();
        args.insert("svc".to_owned(), "nginx".to_owned());
        let r = BashRunner.run(&ctx("echo \"$ARG_svc\"", &args, 5));
        assert!(r.stdout.contains("nginx"));
    }

    #[test]
    fn environment_is_clean() {
        let args = BTreeMap::new();
        // SECRET must not leak in: env_clear() removed the parent env.
        std::env::set_var("ARCHANGEL_TEST_SECRET", "leaked");
        let r = BashRunner.run(&ctx("echo \"${ARCHANGEL_TEST_SECRET:-clean}\"", &args, 5));
        std::env::remove_var("ARCHANGEL_TEST_SECRET");
        assert!(r.stdout.contains("clean"));
        assert!(!r.stdout.contains("leaked"));
    }

    #[test]
    fn timeout_kills_a_hung_action() {
        let args = BTreeMap::new();
        let r = BashRunner.run(&ctx("sleep 30", &args, 1));
        assert_eq!(r.exit_code, -1, "killed action reports -1");
        assert!(r.duration_ms < 5_000, "must not wait the full sleep");
    }

    #[test]
    fn output_is_capped() {
        let args = BTreeMap::new();
        let rc = RunContext {
            script: "yes ABCDEFGH | head -c 100000",
            args: &args,
            timeout: Duration::from_secs(5),
            max_output: 1024,
        };
        let r = BashRunner.run(&rc);
        assert!(r.truncated);
        assert!(r.stdout.len() <= 1024);
    }
}
