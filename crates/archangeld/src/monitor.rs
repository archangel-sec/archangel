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

    use super::{LogTailer, MonitorLimits};

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
}
