//! Real-time log monitoring — the sensory foundation for autonomous mode.
//!
//! This module incrementally tails files (e.g. under `/var/log`) and emits
//! the new lines. It is deliberately the *narrowest possible* capability:
//! it only **reads** and **bounds**, and it never interprets, matches, or
//! acts on anything it sees.
//!
//! # Logs are hostile (threat model T6)
//!
//! Every byte read here is attacker-controllable: any process that can write
//! to a watched log can plant a prompt-injection payload, a forged
//! delimiter, or a flood. Two consequences are baked in:
//!
//! - **Bounding (anti-flood / cost control).** Each poll yields at most
//!   `max_lines_per_poll` lines, and each line is truncated to
//!   `max_line_bytes`. A process spamming a log therefore cannot exhaust the
//!   daemon's memory nor run up unbounded model cost — it just gets shed,
//!   poll by poll.
//! - **Spotlighting is the caller's contract.** A [`LogEvent`]'s `line` is
//!   still hostile text. It MUST be wrapped with
//!   [`crate::prompt::PromptBuilder::wrap_untrusted`] before it is ever
//!   placed in a model prompt; this module does not do that itself so the
//!   sensing stays decoupled and independently testable.
//!
//! Tailing is incremental (a byte offset per file) and rotation-aware: if a
//! file becomes shorter than the last offset (truncated or rotated in place)
//! the offset resets to the start. A file that does not yet exist is not an
//! error — it simply yields nothing until it appears.

use std::{
    fs::File,
    io::{BufRead as _, BufReader, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use regex::{RegexSet, RegexSetBuilder};
use tracing::warn;

/// Compile-time memory ceiling per pattern set — a hostile or fat-fingered
/// pattern cannot make compilation blow up.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Per-poll bounds. Both default conservatively; a flood is shed, not
/// buffered.
#[derive(Debug, Clone, Copy)]
pub struct MonitorLimits {
    /// Lines longer than this are truncated (and flagged); the rest of the
    /// over-long line is discarded, not re-read as a new line.
    pub max_line_bytes: usize,
    /// At most this many lines are returned per [`LogTailer::poll`]; the
    /// remainder stays in the file for the next poll.
    pub max_lines_per_poll: usize,
}

impl Default for MonitorLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 4096,
            max_lines_per_poll: 256,
        }
    }
}

/// One observed log line, already length-bounded.
///
/// The `line` is **hostile** input (T6) and must be spotlighted before it
/// reaches the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// The file the line came from.
    pub source: PathBuf,
    /// The line content, newline stripped and bounded to `max_line_bytes`
    /// (UTF-8 lossy). Still untrusted.
    pub line: String,
    /// Whether the line was truncated at `max_line_bytes`.
    pub truncated: bool,
}

/// Incremental, rotation-aware tailer for a single file.
#[derive(Debug)]
pub struct LogTailer {
    path: PathBuf,
    offset: u64,
    limits: MonitorLimits,
}

impl LogTailer {
    /// Watch `path`, starting from its **current end** so only lines written
    /// after construction are seen (like `tail -f`). A missing file starts
    /// at offset 0 and is picked up when it appears.
    #[must_use]
    pub fn new(path: PathBuf, limits: MonitorLimits) -> Self {
        let offset = std::fs::metadata(&path).map_or(0, |m| m.len());
        Self {
            path,
            offset,
            limits,
        }
    }

    /// Watch `path` from the very beginning (offset 0). Mainly for tests and
    /// one-shot ingestion of an existing file.
    #[must_use]
    pub const fn from_start(path: PathBuf, limits: MonitorLimits) -> Self {
        Self {
            path,
            offset: 0,
            limits,
        }
    }

    /// The watched path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read newly-appended complete lines since the last poll.
    ///
    /// Only whole (newline-terminated) lines are consumed; a trailing
    /// partial line is left in place until it is completed. The byte offset
    /// advances only past consumed lines, so nothing is read twice and
    /// nothing is dropped.
    ///
    /// # Errors
    /// Returns any I/O error other than "file not found" (which yields an
    /// empty batch — a not-yet-created log is normal, not a failure).
    pub fn poll(&mut self) -> std::io::Result<Vec<LogEvent>> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        // Rotation / truncation: a file shorter than our offset was replaced
        // or truncated in place — restart from its beginning.
        let len = file.metadata()?.len();
        if len < self.offset {
            self.offset = 0;
        }

        file.seek(SeekFrom::Start(self.offset))?;
        let mut reader = BufReader::new(file);
        let mut events = Vec::new();
        let mut consumed: u64 = 0;

        for _ in 0..self.limits.max_lines_per_poll {
            let mut buf = Vec::new();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break; // EOF
            }
            if buf.last() != Some(&b'\n') {
                // Partial line (no newline yet): leave it for a later poll.
                break;
            }
            consumed = consumed.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            // Strip the trailing '\n', and a preceding '\r' so CRLF logs do
            // not carry it into prompts.
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }

            let truncated = buf.len() > self.limits.max_line_bytes;
            let bytes = buf.get(..self.limits.max_line_bytes).unwrap_or(&buf);
            events.push(LogEvent {
                source: self.path.clone(),
                line: String::from_utf8_lossy(bytes).into_owned(),
                truncated,
            });
        }

        self.offset = self.offset.saturating_add(consumed);
        Ok(events)
    }
}

/// An operator-defined trigger pattern: the pre-filter for the model.
///
/// It decides which log lines are even worth the model's attention. The
/// operator — not the model — controls this list, so the autonomous loop
/// only ever reacts to events the operator opted into watching.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Human label (audit / which trigger fired).
    pub label: String,
    /// The (linear-time) regular expression to match against a log line.
    pub regex: String,
}

/// Why a monitor could not be built.
#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    /// A trigger pattern did not compile (reported with its label so the
    /// operator can fix the offending entry).
    #[error("invalid monitor pattern {label:?}: {source}")]
    BadPattern {
        /// The label of the offending pattern.
        label: String,
        /// The underlying regex error.
        source: regex::Error,
    },
    /// The combined pattern set exceeded the compile-size ceiling.
    #[error("monitor pattern set too large: {0}")]
    SetTooLarge(regex::Error),
}

/// A compiled set of trigger patterns.
///
/// Built on the `regex` crate, which guarantees linear-time matching — a
/// hostile log line (T6) cannot trigger catastrophic backtracking. Same
/// anti-ReDoS basis as the denylist.
#[derive(Debug)]
pub struct LogMatcher {
    set: RegexSet,
    labels: Vec<String>,
}

impl LogMatcher {
    /// Compile the operator's trigger patterns. Fail-closed: a single bad
    /// pattern refuses the whole set (named by its label).
    ///
    /// # Errors
    /// [`MonitorError::BadPattern`] / [`MonitorError::SetTooLarge`].
    pub fn compile(patterns: &[Pattern]) -> Result<Self, MonitorError> {
        // Validate each pattern individually first so the error names the
        // offending label (a `RegexSet` build error would not).
        for p in patterns {
            RegexSetBuilder::new([&p.regex])
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|source| MonitorError::BadPattern {
                    label: p.label.clone(),
                    source,
                })?;
        }
        let set = RegexSetBuilder::new(patterns.iter().map(|p| &p.regex))
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(MonitorError::SetTooLarge)?;
        Ok(Self {
            set,
            labels: patterns.iter().map(|p| p.label.clone()).collect(),
        })
    }

    /// Labels of every pattern that matches `line` (empty ⇒ not a trigger).
    #[must_use]
    pub fn matches(&self, line: &str) -> Vec<String> {
        self.set
            .matches(line)
            .into_iter()
            .filter_map(|i| self.labels.get(i).cloned())
            .collect()
    }

    /// True if there are no patterns (so nothing is ever a trigger).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// A matched log line: an event whose content fired one or more triggers.
/// Its `event.line` is still **hostile** — spotlight before any model use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The observed (bounded) log line.
    pub event: LogEvent,
    /// Labels of the trigger patterns that fired.
    pub matched: Vec<String>,
}

/// Watches a set of files and surfaces only the lines that fire a trigger.
///
/// This is the complete *read-only* sensing layer for autonomous mode: it
/// observes and screens, full stop. It performs no model call and takes no
/// action — those belong to the (separately built, gate-respecting) decision
/// loop that consumes these alerts.
#[derive(Debug)]
pub struct LogMonitor {
    tailers: Vec<LogTailer>,
    matcher: LogMatcher,
}

impl LogMonitor {
    /// Build a monitor over `sources`, screening with `patterns`.
    ///
    /// # Errors
    /// Propagates [`LogMatcher::compile`] failures (fail-closed).
    pub fn new(
        sources: Vec<PathBuf>,
        limits: MonitorLimits,
        patterns: &[Pattern],
    ) -> Result<Self, MonitorError> {
        let matcher = LogMatcher::compile(patterns)?;
        let tailers = sources
            .into_iter()
            .map(|p| LogTailer::new(p, limits))
            .collect();
        Ok(Self { tailers, matcher })
    }

    /// Poll every watched file and return the new lines that fired a trigger.
    /// A per-file I/O error (e.g. a permission change) is logged and skipped
    /// for this round, never fatal — one unreadable log must not blind the
    /// monitor to the others.
    pub fn poll(&mut self) -> Vec<Alert> {
        // Split the borrows so the matcher can be used while tailers iterate.
        let Self { tailers, matcher } = self;
        let mut alerts = Vec::new();
        for tailer in tailers.iter_mut() {
            match tailer.poll() {
                Ok(events) => {
                    for event in events {
                        let matched = matcher.matches(&event.line);
                        if !matched.is_empty() {
                            alerts.push(Alert { event, matched });
                        }
                    }
                }
                Err(err) => warn!(
                    path = %tailer.path().display(),
                    %err,
                    "log poll failed; skipping this source for this round"
                ),
            }
        }
        alerts
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::Write as _,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::{LogMatcher, LogMonitor, LogTailer, MonitorError, MonitorLimits, Pattern};

    fn pat(label: &str, regex: &str) -> Pattern {
        Pattern {
            label: label.to_owned(),
            regex: regex.to_owned(),
        }
    }

    fn tmp_log() -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "archangel-mon-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn append(path: &std::path::Path, data: &str) {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open for append");
        f.write_all(data.as_bytes()).expect("append");
    }

    #[test]
    fn reads_appended_lines_incrementally() {
        let p = tmp_log();
        append(&p, "first\n");
        // from_start sees existing content.
        let mut t = LogTailer::from_start(p.clone(), MonitorLimits::default());
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "first");
        assert!(!batch[0].truncated);

        // Nothing new yet.
        assert!(t.poll().expect("poll").is_empty());

        // Append more; only the new lines come back.
        append(&p, "second\nthird\n");
        let batch = t.poll().expect("poll");
        let lines: Vec<_> = batch.iter().map(|e| e.line.as_str()).collect();
        assert_eq!(lines, ["second", "third"]);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn new_starts_at_end_ignoring_history() {
        let p = tmp_log();
        append(&p, "old-1\nold-2\n");
        let mut t = LogTailer::new(p.clone(), MonitorLimits::default());
        // Pre-existing lines are not surfaced.
        assert!(t.poll().expect("poll").is_empty());
        append(&p, "new-1\n");
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "new-1");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn partial_line_is_held_until_completed() {
        let p = tmp_log();
        let mut t = LogTailer::from_start(p.clone(), MonitorLimits::default());
        append(&p, "incompl");
        // No newline yet ⇒ nothing consumed.
        assert!(t.poll().expect("poll").is_empty());
        append(&p, "ete\n");
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "incomplete");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn overlong_line_is_truncated_and_flagged() {
        let p = tmp_log();
        let limits = MonitorLimits {
            max_line_bytes: 8,
            max_lines_per_poll: 256,
        };
        let mut t = LogTailer::from_start(p.clone(), limits);
        append(&p, "0123456789ABCDEF\nshort\n");
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].line, "01234567");
        assert!(batch[0].truncated);
        assert_eq!(batch[1].line, "short");
        assert!(!batch[1].truncated);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn poll_is_bounded_and_the_rest_waits() {
        let p = tmp_log();
        let limits = MonitorLimits {
            max_line_bytes: 4096,
            max_lines_per_poll: 2,
        };
        let mut t = LogTailer::from_start(p.clone(), limits);
        append(&p, "a\nb\nc\nd\n");
        let first = t.poll().expect("poll");
        assert_eq!(first.len(), 2, "a flood is shed to the cap per poll");
        let second = t.poll().expect("poll");
        assert_eq!(second.len(), 2, "the remainder is read next poll");
        let lines: Vec<_> = first
            .iter()
            .chain(&second)
            .map(|e| e.line.clone())
            .collect();
        assert_eq!(lines, ["a", "b", "c", "d"]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rotation_resets_to_start() {
        let p = tmp_log();
        append(&p, "before-rotation\n");
        let mut t = LogTailer::from_start(p.clone(), MonitorLimits::default());
        assert_eq!(t.poll().expect("poll").len(), 1);
        // Simulate truncate-in-place rotation: replace with a shorter file.
        std::fs::write(&p, "after\n").expect("rewrite");
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "after");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let p = tmp_log(); // never created
        let mut t = LogTailer::new(p.clone(), MonitorLimits::default());
        assert!(t.poll().expect("poll on missing file").is_empty());
        // It is picked up once it appears.
        append(&p, "appeared\n");
        let batch = t.poll().expect("poll");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].line, "appeared");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn crlf_is_normalized() {
        let p = tmp_log();
        let mut t = LogTailer::from_start(p.clone(), MonitorLimits::default());
        append(&p, "windows\r\nunix\n");
        let batch = t.poll().expect("poll");
        assert_eq!(batch[0].line, "windows");
        assert_eq!(batch[1].line, "unix");
        let _ = std::fs::remove_file(&p);
    }

    // --- pattern matcher / monitor ---

    #[test]
    fn matcher_returns_labels_of_firing_patterns() {
        let m = LogMatcher::compile(&[
            pat("oom", "Out of memory"),
            pat("error", "(?i)error"),
            pat("ssh-fail", "Failed password"),
        ])
        .expect("compile");
        assert_eq!(m.matches("kernel: Out of memory: Killed process"), ["oom"]);
        assert_eq!(m.matches("sshd: Failed password for root"), ["ssh-fail"]);
        // Case-insensitive pattern fires on mixed case; only that one.
        assert_eq!(m.matches("ERROR: disk full"), ["error"]);
        // A benign line fires nothing (not a trigger).
        assert!(m.matches("normal heartbeat ok").is_empty());
    }

    #[test]
    fn matcher_can_fire_multiple_labels() {
        let m = LogMatcher::compile(&[pat("error", "(?i)error"), pat("disk", "disk")])
            .expect("compile");
        let labels = m.matches("error: disk full");
        assert!(labels.contains(&"error".to_owned()));
        assert!(labels.contains(&"disk".to_owned()));
    }

    #[test]
    fn bad_pattern_is_refused_with_its_label() {
        let err = LogMatcher::compile(&[pat("ok", "fine"), pat("broken", "(unclosed")])
            .expect_err("must reject");
        assert!(
            matches!(&err, MonitorError::BadPattern { label, .. } if label == "broken"),
            "expected BadPattern(broken), got {err:?}"
        );
    }

    #[test]
    fn empty_patterns_match_nothing() {
        let m = LogMatcher::compile(&[]).expect("compile empty");
        assert!(m.is_empty());
        assert!(m.matches("anything at all").is_empty());
    }

    #[test]
    fn monitor_surfaces_only_matching_lines() {
        let p = tmp_log();
        let mut mon = LogMonitor::new(
            vec![p.clone()],
            MonitorLimits::default(),
            &[pat("error", "(?i)error")],
        )
        .expect("monitor");
        // Nothing yet (starts at end / empty file).
        assert!(mon.poll().is_empty());
        append(&p, "info: all good\nERROR: tank empty\ninfo: still fine\n");
        let alerts = mon.poll();
        assert_eq!(alerts.len(), 1, "only the error line is a trigger");
        assert_eq!(alerts[0].event.line, "ERROR: tank empty");
        assert_eq!(alerts[0].matched, ["error"]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn monitor_with_no_patterns_never_alerts() {
        let p = tmp_log();
        let mut mon =
            LogMonitor::new(vec![p.clone()], MonitorLimits::default(), &[]).expect("monitor");
        append(&p, "ERROR: but no patterns configured\n");
        assert!(mon.poll().is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
