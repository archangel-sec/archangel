//! cgroup v2 resource-limit parsing **and** application.
//!
//! [`CpuMax`] / [`MemoryMax`] parse bundle-declared `cpu_max` / `memory_max`
//! strings into the exact bytes the kernel expects in `cpu.max` /
//! `memory.max`. Parsing is strict and total: a malformed, zero, negative,
//! overflowing, or out-of-range value is [`SandboxError::InvalidLimit`] — it
//! is **never** interpreted as "unlimited". A bundle cannot escape its cage
//! with a typo.
//!
//! [`Cgroup`] then *applies* a parsed limit: it creates a per-action child
//! cgroup under the executor's own cgroup, writes the controller files, and
//! (the caller) moves the action process into it. This half is fail-closed
//! too — a declared limit that cannot be written is [`SandboxError::CgroupFailed`],
//! never silently dropped — but it only runs when a bundle actually declares
//! a limit; bundles with none do no cgroup work at all.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::SandboxError;

/// cgroup v2 `cpu.max` enforcement period (microseconds). Quota is expressed
/// against this fixed window, matching the kernel default.
const CPU_PERIOD_US: u64 = 100_000;

/// Upper bound on a declared CPU percentage. v0.2 caps an action at one
/// core-equivalent; a bundle asking for more is rejected rather than
/// silently granted (conservative, documented in `docs/SANDBOX.md`).
const MAX_CPU_PERCENT: u64 = 100;

/// Sanity ceiling on a declared memory limit (1 TiB). Anything larger is
/// almost certainly a unit mistake and is refused rather than treated as a
/// near-unbounded limit.
const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// A validated CPU ceiling, ready to write to cgroup v2 `cpu.max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    percent: u64,
}

impl CpuMax {
    /// Parse a `"<n>%"` CPU ceiling (e.g. `"10%"`).
    ///
    /// # Errors
    /// [`SandboxError::InvalidLimit`] if not `<positive integer>%`, if zero,
    /// or if it exceeds [`MAX_CPU_PERCENT`].
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let s = s.trim();
        let digits = s.strip_suffix('%').ok_or_else(|| {
            SandboxError::InvalidLimit(format!("cpu_max {s:?}: expected \"<n>%\""))
        })?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SandboxError::InvalidLimit(format!(
                "cpu_max {s:?}: non-integer percentage"
            )));
        }
        let percent: u64 = digits.parse().map_err(|_| {
            SandboxError::InvalidLimit(format!("cpu_max {s:?}: percentage overflow"))
        })?;
        if percent == 0 {
            return Err(SandboxError::InvalidLimit(
                "cpu_max \"0%\": a zero quota would wedge the action".to_owned(),
            ));
        }
        if percent > MAX_CPU_PERCENT {
            return Err(SandboxError::InvalidLimit(format!(
                "cpu_max {percent}% exceeds the {MAX_CPU_PERCENT}% ceiling"
            )));
        }
        Ok(Self { percent })
    }

    /// The exact `cpu.max` file contents: `"<quota_us> <period_us>"`.
    #[must_use]
    pub fn cgroup_value(self) -> String {
        // percent ≤ 100, so percent*CPU_PERIOD_US ≤ 10_000_000: no overflow.
        // `div_euclid` (not `/`) keeps clippy's integer-division lint clear
        // and the result exact (CPU_PERIOD_US is a multiple of 100).
        let quota = self.percent.saturating_mul(CPU_PERIOD_US).div_euclid(100);
        format!("{quota} {CPU_PERIOD_US}")
    }
}

/// A validated memory ceiling, ready to write to cgroup v2 `memory.max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryMax {
    bytes: u64,
}

impl MemoryMax {
    /// Parse a memory ceiling: a plain byte count (`"1048576"`) or a
    /// `K`/`M`/`G`-suffixed binary size (`"128M"`, `"1G"`, case-insensitive).
    ///
    /// # Errors
    /// [`SandboxError::InvalidLimit`] if empty, zero, non-numeric, an
    /// unknown unit, overflowing, or above [`MAX_MEMORY_BYTES`].
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SandboxError::InvalidLimit("memory_max: empty".to_owned()));
        }
        let bad = |m: String| SandboxError::InvalidLimit(m);

        let (num_part, multiplier): (&str, u64) = if let Some(p) = s.strip_suffix(['k', 'K']) {
            (p, 1024)
        } else if let Some(p) = s.strip_suffix(['m', 'M']) {
            (p, 1024 * 1024)
        } else if let Some(p) = s.strip_suffix(['g', 'G']) {
            (p, 1024 * 1024 * 1024)
        } else if s.ends_with(|c: char| c.is_ascii_digit()) {
            (s, 1)
        } else {
            return Err(bad(format!(
                "memory_max {s:?}: unknown unit (use K/M/G or raw bytes)"
            )));
        };
        if num_part.is_empty() || !num_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad(format!("memory_max {s:?}: non-integer amount")));
        }
        let value: u64 = num_part
            .parse()
            .map_err(|_| bad(format!("memory_max {s:?}: amount overflow")))?;
        let bytes = value
            .checked_mul(multiplier)
            .ok_or_else(|| bad(format!("memory_max {s:?}: byte count overflow")))?;
        if bytes == 0 {
            return Err(bad(
                "memory_max: zero would make every allocation fail".to_owned()
            ));
        }
        if bytes > MAX_MEMORY_BYTES {
            return Err(bad(format!(
                "memory_max {bytes} bytes exceeds the sanity ceiling \
                 ({MAX_MEMORY_BYTES} bytes); likely a unit mistake"
            )));
        }
        Ok(Self { bytes })
    }

    /// The exact `memory.max` file contents (a decimal byte count).
    #[must_use]
    pub fn cgroup_value(self) -> String {
        self.bytes.to_string()
    }

    /// The resolved limit in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Where the unified cgroup v2 hierarchy is mounted.
const CGROUP_V2_MOUNT: &str = "/sys/fs/cgroup";

/// Parse the v2 cgroup path of the calling process from the contents of
/// `/proc/self/cgroup`. The unified hierarchy is the single line beginning
/// `0::`; its value is an absolute path *within* the hierarchy (e.g.
/// `/system.slice/archangel-execd.service`). Returns `None` if there is no
/// v2 line (e.g. a pure cgroup-v1 host) — the caller then fails closed.
fn parse_self_cgroup_v2(proc_content: &str) -> Option<String> {
    proc_content.lines().find_map(|line| {
        // Format: `hierarchy-ID:controllers:path`; v2 is `0::<path>`.
        let rest = line.strip_prefix("0::")?;
        if rest.starts_with('/') {
            Some(rest.to_owned())
        } else {
            None
        }
    })
}

/// A per-action cgroup v2 directory holding the action's resource limits.
///
/// Created as a child of the executor's own cgroup so it inherits the
/// controllers systemd delegated (`Delegate=yes`). Dropping it removes the
/// directory (best effort); the kernel only allows that once the cgroup is
/// empty, i.e. after the action process has exited.
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
}

/// A child cgroup directory name must be a single safe component.
fn safe_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains('/')
        && !name.contains('\0')
        && name != "."
        && name != ".."
}

impl Cgroup {
    /// Create a per-action cgroup named `name` under the executor's own v2
    /// cgroup and write the declared limits. Returns `Ok(None)` when neither
    /// limit is set (nothing to enforce ⇒ no cgroup work).
    ///
    /// # Errors
    /// [`SandboxError::CgroupFailed`] if the v2 hierarchy cannot be located
    /// or the cgroup/controller files cannot be created or written.
    /// Fail-closed: a declared limit that cannot be applied refuses the
    /// action rather than running it unbounded.
    pub fn create_for_self(
        name: &str,
        cpu: Option<CpuMax>,
        memory: Option<MemoryMax>,
    ) -> Result<Option<Self>, SandboxError> {
        if cpu.is_none() && memory.is_none() {
            return Ok(None);
        }
        let proc = fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| SandboxError::CgroupFailed(format!("read /proc/self/cgroup: {e}")))?;
        let rel = parse_self_cgroup_v2(&proc).ok_or_else(|| {
            SandboxError::CgroupFailed(
                "no cgroup v2 (unified) hierarchy for this process".to_owned(),
            )
        })?;
        // `rel` is absolute within the hierarchy; strip the leading `/` so it
        // joins under the mount point.
        let root = Path::new(CGROUP_V2_MOUNT).join(rel.trim_start_matches('/'));
        Self::create_under(&root, name, cpu, memory).map(Some)
    }

    /// Lower-level: create `name` under an explicit `parent` cgroup dir and
    /// write the limits. Factored out so the file behaviour is unit-tested
    /// against a temporary directory without a real cgroup mount.
    fn create_under(
        parent: &Path,
        name: &str,
        cpu: Option<CpuMax>,
        memory: Option<MemoryMax>,
    ) -> Result<Self, SandboxError> {
        if !safe_component(name) {
            return Err(SandboxError::CgroupFailed(format!(
                "unsafe cgroup name {name:?}"
            )));
        }
        let path = parent.join(name);
        fs::create_dir(&path)
            .map_err(|e| SandboxError::CgroupFailed(format!("create {}: {e}", path.display())))?;
        let cg = Self { path };
        // From here on, any failure cleans up via `cg`'s Drop.
        if let Some(c) = cpu {
            cg.write_file("cpu.max", &c.cgroup_value())?;
        }
        if let Some(m) = memory {
            cg.write_file("memory.max", &m.cgroup_value())?;
        }
        Ok(cg)
    }

    fn write_file(&self, file: &str, value: &str) -> Result<(), SandboxError> {
        let target = self.path.join(file);
        fs::write(&target, value)
            .map_err(|e| SandboxError::CgroupFailed(format!("write {}: {e}", target.display())))
    }

    /// Move a process into this cgroup (so its resource usage is bounded).
    ///
    /// # Errors
    /// [`SandboxError::CgroupFailed`] if `cgroup.procs` cannot be written.
    pub fn add_pid(&self, pid: u32) -> Result<(), SandboxError> {
        self.write_file("cgroup.procs", &pid.to_string())
    }

    /// The cgroup directory path (diagnostics / tests).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Best effort: only succeeds once the cgroup is empty (process gone).
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{CpuMax, MemoryMax, MAX_MEMORY_BYTES};
    use crate::SandboxError;

    fn is_invalid(r: Result<impl core::fmt::Debug, SandboxError>) -> bool {
        matches!(r.err(), Some(SandboxError::InvalidLimit(_)))
    }

    #[test]
    fn cpu_percent_maps_to_quota_period() {
        assert_eq!(CpuMax::parse("10%").unwrap().cgroup_value(), "10000 100000");
        assert_eq!(
            CpuMax::parse("100%").unwrap().cgroup_value(),
            "100000 100000"
        );
        assert_eq!(
            CpuMax::parse(" 25% ").unwrap().cgroup_value(),
            "25000 100000"
        );
    }

    #[test]
    fn cpu_rejects_garbage_zero_and_over_ceiling() {
        for bad in [
            "", "%", "10", "abc%", "-5%", "10 %", "0%", "101%", "1000%", "10%%", "1e3%",
        ] {
            assert!(
                is_invalid(CpuMax::parse(bad)),
                "cpu_max {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn memory_units_and_raw_bytes() {
        assert_eq!(MemoryMax::parse("128M").unwrap().bytes(), 128 * 1024 * 1024);
        assert_eq!(MemoryMax::parse("1G").unwrap().bytes(), 1024 * 1024 * 1024);
        assert_eq!(MemoryMax::parse("512k").unwrap().bytes(), 512 * 1024);
        assert_eq!(MemoryMax::parse("1048576").unwrap().bytes(), 1_048_576);
        assert_eq!(
            MemoryMax::parse("64M").unwrap().cgroup_value(),
            (64 * 1024 * 1024).to_string()
        );
    }

    #[test]
    fn memory_rejects_garbage_zero_overflow_and_unknown_units() {
        for bad in [
            "",
            " ",
            "M",
            "abc",
            "12X",
            "12.5M",
            "-1",
            "0",
            "0M",
            "0G",
            "99999999999999999999999999G", // value overflow
            "18446744073709551615K",       // *1024 overflows u64
            "2T",                          // unknown unit
        ] {
            assert!(
                is_invalid(MemoryMax::parse(bad)),
                "memory_max {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn memory_rejects_above_sanity_ceiling() {
        let over = (MAX_MEMORY_BYTES + 1).to_string();
        assert!(is_invalid(MemoryMax::parse(&over)));
        // Exactly at the ceiling is allowed.
        assert!(MemoryMax::parse(&MAX_MEMORY_BYTES.to_string()).is_ok());
    }

    // --- cgroup application (file behaviour, against a temp dir) ---

    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::{parse_self_cgroup_v2, safe_component, Cgroup};

    fn tmp_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "archangel-cg-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).expect("temp parent");
        p
    }

    #[test]
    fn parses_unified_cgroup_line() {
        let content = "0::/system.slice/archangel-execd.service\n";
        assert_eq!(
            parse_self_cgroup_v2(content).as_deref(),
            Some("/system.slice/archangel-execd.service")
        );
    }

    #[test]
    fn ignores_v1_only_content() {
        // A pure cgroup-v1 host has no `0::` line ⇒ None ⇒ caller fails closed.
        let content = "12:pids:/\n4:memory:/user.slice\n1:cpu:/\n";
        assert_eq!(parse_self_cgroup_v2(content), None);
    }

    #[test]
    fn picks_v2_line_among_v1_lines() {
        let content = "5:cpu:/legacy\n0::/the/unified/path\n3:pids:/x\n";
        assert_eq!(
            parse_self_cgroup_v2(content).as_deref(),
            Some("/the/unified/path")
        );
    }

    #[test]
    fn no_limits_creates_no_cgroup() {
        let r = Cgroup::create_for_self("action-x", None, None).expect("no-op must succeed");
        assert!(r.is_none(), "no declared limits ⇒ no cgroup created");
    }

    #[test]
    fn writes_controller_files_and_moves_pid() {
        let parent = tmp_dir();
        let cpu = CpuMax::parse("10%").unwrap();
        let mem = MemoryMax::parse("128M").unwrap();
        let cg =
            Cgroup::create_under(&parent, "action-1", Some(cpu), Some(mem)).expect("create cgroup");

        assert_eq!(
            fs::read_to_string(cg.path().join("cpu.max")).unwrap(),
            "10000 100000"
        );
        assert_eq!(
            fs::read_to_string(cg.path().join("memory.max")).unwrap(),
            (128 * 1024 * 1024).to_string()
        );

        cg.add_pid(4242).expect("write cgroup.procs");
        assert_eq!(
            fs::read_to_string(cg.path().join("cgroup.procs")).unwrap(),
            "4242"
        );
        let path = cg.path().to_path_buf();
        drop(cg);
        // Our temp `cgroup.procs`/`*.max` are plain files (not the kernel's
        // magic empties-on-exit ones), so the dir isn't empty and the
        // best-effort rmdir is a no-op here — that's fine; on a real cgroup
        // the kernel removes the control files once the procs list empties.
        assert!(path.exists());
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn only_cpu_writes_only_cpu_max() {
        let parent = tmp_dir();
        let cpu = CpuMax::parse("50%").unwrap();
        let cg = Cgroup::create_under(&parent, "action-2", Some(cpu), None).expect("create");
        assert!(cg.path().join("cpu.max").exists());
        assert!(!cg.path().join("memory.max").exists());
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn unsafe_name_is_refused() {
        let parent = tmp_dir();
        let cpu = CpuMax::parse("10%").unwrap();
        for bad in ["../escape", "a/b", "", "."] {
            assert!(matches!(
                Cgroup::create_under(&parent, bad, Some(cpu), None),
                Err(SandboxError::CgroupFailed(_))
            ));
        }
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn safe_component_accepts_action_names() {
        assert!(safe_component("action-deadbeef"));
        assert!(!safe_component("a/b"));
        assert!(!safe_component(".."));
        assert!(!safe_component(""));
    }
}
