//! `archangel-doctor`: host readiness preflight.
//!
//! Pre-alpha archangel relies on specific kernel/systemd features. This is
//! a **read-only** check (no privilege, no mutation) the operator runs
//! before the first session so failures surface as a clear report instead
//! of a confusing daemon crash. It is advisory: it never weakens anything,
//! it only tells you what is missing.

use std::path::Path;

use crate::render::{trusted_line, Block, Palette};

/// Severity of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Requirement satisfied.
    Pass,
    /// Works but sub-optimal / should be reviewed.
    Warn,
    /// Hard requirement missing — the daemon will not work correctly.
    Fail,
}

/// One check outcome.
#[derive(Debug, Clone)]
pub struct Check {
    /// Short check name.
    pub name: &'static str,
    /// Result.
    pub severity: Severity,
    /// Human-readable detail.
    pub detail: String,
}

/// The full preflight report.
#[derive(Debug, Default)]
pub struct Report {
    /// All checks, in evaluation order.
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: &'static str, severity: Severity, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            severity,
            detail: detail.into(),
        });
    }

    /// `true` iff no check failed (warnings are tolerated).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        !self.checks.iter().any(|c| c.severity == Severity::Fail)
    }

    /// Render the report for the terminal.
    #[must_use]
    pub fn render(&self, palette: Palette) -> String {
        let mut out = String::new();
        for c in &self.checks {
            let block = match c.severity {
                Severity::Pass => Block::Status,
                Severity::Warn => Block::Proposal,
                Severity::Fail => Block::Error,
            };
            let tag = match c.severity {
                Severity::Pass => "PASS",
                Severity::Warn => "WARN",
                Severity::Fail => "FAIL",
            };
            out.push_str(&trusted_line(
                palette,
                block,
                &format!("[{tag}] {:<22} {}", c.name, c.detail),
            ));
            out.push('\n');
        }
        let summary = if self.is_ok() {
            "host looks ready (review any WARN lines)".to_owned()
        } else {
            "host is NOT ready — resolve every FAIL before running archangel".to_owned()
        };
        out.push_str(&trusted_line(
            palette,
            if self.is_ok() {
                Block::Status
            } else {
                Block::Error
            },
            &summary,
        ));
        out
    }
}

/// Parse `MAJOR.MINOR` from a kernel release string like `6.6.1-foo`.
fn kernel_major_minor(release: &str) -> Option<(u32, u32)> {
    let mut it = release.split(['.', '-']);
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

/// Run all probes against the live system.
#[must_use]
pub fn diagnose(etc_dir: &Path, operator_key: &Path) -> Report {
    let mut r = Report::default();

    match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(rel) => match kernel_major_minor(rel.trim()) {
            Some((maj, min)) if (maj, min) >= (5, 10) => {
                r.push(
                    "kernel",
                    Severity::Pass,
                    format!("{} (>= 5.10)", rel.trim()),
                );
            }
            Some((maj, min)) => r.push(
                "kernel",
                Severity::Fail,
                format!("{maj}.{min} < 5.10 (seccomp v2 / userns requirements)"),
            ),
            None => r.push("kernel", Severity::Warn, "could not parse kernel version"),
        },
        Err(e) => r.push("kernel", Severity::Warn, format!("unknown: {e}")),
    }

    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        r.push("cgroup v2", Severity::Pass, "unified hierarchy present");
    } else {
        r.push(
            "cgroup v2",
            Severity::Fail,
            "/sys/fs/cgroup/cgroup.controllers missing (per-action limits need cgroup v2)",
        );
    }

    if Path::new("/run/systemd/system").exists() {
        r.push("systemd", Severity::Pass, "booted with systemd");
    } else {
        r.push(
            "systemd",
            Severity::Warn,
            "not a systemd boot — units won't manage the daemons",
        );
    }

    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(v) if v.trim() == "1" => {
            r.push(
                "user namespaces",
                Severity::Pass,
                "unprivileged userns enabled",
            );
        }
        Ok(_) => r.push(
            "user namespaces",
            Severity::Warn,
            "unprivileged userns disabled — sandbox (v0.2) will need adjustment",
        ),
        Err(_) => r.push(
            "user namespaces",
            Severity::Warn,
            "cannot determine userns policy (kernel default assumed)",
        ),
    }

    if etc_dir.is_dir() {
        r.push(
            "config dir",
            Severity::Pass,
            format!("{} present", etc_dir.display()),
        );
    } else {
        r.push(
            "config dir",
            Severity::Fail,
            format!("{} missing", etc_dir.display()),
        );
    }

    if operator_key.exists() {
        r.push(
            "operator key",
            Severity::Pass,
            format!("{} present", operator_key.display()),
        );
    } else {
        r.push(
            "operator key",
            Severity::Fail,
            format!(
                "{} missing — run `archangelctl init`",
                operator_key.display()
            ),
        );
    }

    r
}

#[cfg(test)]
mod tests {
    use super::{kernel_major_minor, Check, Report, Severity};
    use crate::render::Palette;

    #[test]
    fn parses_kernel_versions() {
        assert_eq!(kernel_major_minor("6.6.114-microsoft"), Some((6, 6)));
        assert_eq!(kernel_major_minor("5.10.0"), Some((5, 10)));
        assert_eq!(kernel_major_minor("garbage"), None);
    }

    #[test]
    fn report_ok_only_without_failures() {
        let mut r = Report::default();
        r.checks.push(Check {
            name: "a",
            severity: Severity::Pass,
            detail: "ok".into(),
        });
        r.checks.push(Check {
            name: "b",
            severity: Severity::Warn,
            detail: "meh".into(),
        });
        assert!(r.is_ok(), "warnings are tolerated");
        r.checks.push(Check {
            name: "c",
            severity: Severity::Fail,
            detail: "bad".into(),
        });
        assert!(!r.is_ok(), "any FAIL means not ready");
    }

    #[test]
    fn render_marks_failure_summary() {
        let mut r = Report::default();
        r.checks.push(Check {
            name: "x",
            severity: Severity::Fail,
            detail: "nope".into(),
        });
        let s = r.render(Palette::fixed(false));
        assert!(s.contains("[FAIL]"));
        assert!(s.contains("NOT ready"));
    }
}
