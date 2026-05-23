//! cgroup v2 resource-limit parsing.
//!
//! Bundle-declared `cpu_max` / `memory_max` strings are parsed here into the
//! exact bytes the kernel expects in `cpu.max` / `memory.max`. Parsing is
//! strict and total: a malformed, zero, negative, overflowing, or
//! out-of-range value is [`SandboxError::InvalidLimit`] — it is **never**
//! interpreted as "unlimited". A bundle cannot escape its cage with a typo.

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
}
