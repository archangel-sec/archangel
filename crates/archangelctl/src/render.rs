//! Secure terminal rendering.
//!
//! # Why this is a security control, not cosmetics
//!
//! `archangelctl` displays three kinds of content with very different
//! trust:
//!
//! - **trusted chrome** archangelctl emits itself (prefixes, the approval
//!   line, the action id),
//! - **untrusted model output** (reasons, questions),
//! - **untrusted command output** (stdout/stderr of an executed action).
//!
//! Untrusted content can contain ANSI/terminal control sequences. Rendered
//! naively, an attacker (via prompt injection or a hostile command output)
//! could move the cursor, clear the screen, or paint a fake
//! `[ APPROVED ]` line that looks like archangelctl's own chrome — and
//! socially engineer the operator. [`sanitize_untrusted`] strips every
//! escape and control byte (except `\n`/`\t`) from untrusted content
//! *before* it is shown, so untrusted text can only ever appear as inert
//! characters. Only this module emits styling, and only around content it
//! produced. That asymmetry is the defense.

use std::fmt::Write as _;

/// Cap on a single untrusted block. A console operator cannot read a
/// megabyte anyway; the cap also bounds memory and limits a flooding peer.
pub const MAX_UNTRUSTED_BYTES: usize = 64 * 1024;

/// Strip terminal-dangerous bytes from untrusted content.
///
/// Keeps printable text plus `\n` and `\t`. Drops ESC (`0x1B`), every other
/// C0 control, DEL, and C1 controls — i.e. everything that could start or
/// form an ANSI/OSC/cursor sequence. The result can be printed inside our
/// own styled block with no risk of it escaping that block.
#[must_use]
pub fn sanitize_untrusted(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_UNTRUSTED_BYTES));
    let mut truncated_at = None;
    for (i, ch) in input.char_indices() {
        if out.len() >= MAX_UNTRUSTED_BYTES {
            truncated_at = Some(i);
            break;
        }
        if ch == '\n' || ch == '\t' || !ch.is_control() {
            out.push(ch);
        }
        // Everything else (ESC, C0, DEL, C1) is dropped.
    }
    if let Some(at) = truncated_at {
        let dropped = input.len().saturating_sub(at);
        let _ = write!(
            out,
            "\n[archangelctl: truncated {dropped} more bytes of untrusted output]"
        );
    }
    out
}

/// ANSI palette. Disabled when not a TTY, under `NO_COLOR`, or by `--no-color`.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    /// A palette honoring `force_off`, `NO_COLOR`, and TTY detection.
    #[must_use]
    pub fn detect(force_off: bool, is_tty: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            enabled: is_tty && !no_color && !force_off,
        }
    }

    /// An explicitly enabled/disabled palette (used by tests).
    #[must_use]
    pub const fn fixed(enabled: bool) -> Self {
        Self { enabled }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

/// The role of a rendered block — drives prefix and color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// What the operator typed (trusted).
    Operator,
    /// archangel's own pipeline/status narration (trusted).
    Status,
    /// A model-proposed action (untrusted — reason is sanitized).
    Proposal,
    /// Captured command output (untrusted — fully sanitized).
    Output,
    /// An approval prompt (trusted chrome; never derivable from untrusted).
    Approval,
    /// An error / denial (trusted).
    Error,
}

impl Block {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Operator => "› ",
            Self::Status => "· ",
            Self::Proposal => "▸ action ",
            Self::Output => "── output ",
            Self::Approval => "?? ",
            Self::Error => "✗ ",
        }
    }

    const fn color(self) -> &'static str {
        match self {
            Self::Operator => "36",   // cyan
            Self::Status => "90",     // bright black / dim
            Self::Proposal => "33",   // yellow
            Self::Output => "37",     // white
            Self::Approval => "1;35", // bold magenta
            Self::Error => "1;31",    // bold red
        }
    }
}

/// Render a **trusted** one-liner (chrome). Content is NOT sanitized
/// because the caller is archangelctl itself.
#[must_use]
pub fn trusted_line(palette: Palette, block: Block, content: &str) -> String {
    palette.paint(block.color(), &format!("{}{content}", block.prefix()))
}

/// Render an **untrusted** block. Content is sanitized first; only the
/// surrounding header/footer carry styling, and they are emitted by us.
#[must_use]
pub fn untrusted_block(
    palette: Palette,
    block: Block,
    label: &str,
    untrusted_content: &str,
) -> String {
    let header = palette.paint(
        block.color(),
        &format!("{}{label} (untrusted — shown inert)", block.prefix()),
    );
    let footer = palette.paint(block.color(), "── end ──");
    let safe = sanitize_untrusted(untrusted_content);
    format!("{header}\n{safe}\n{footer}")
}

#[cfg(test)]
mod tests {
    use super::{
        sanitize_untrusted, trusted_line, untrusted_block, Block, Palette, MAX_UNTRUSTED_BYTES,
    };

    #[test]
    fn strips_ansi_escape_and_control_bytes() {
        let evil = "ok\x1b[2J\x1b[1;1Htext\x07\x00\x1b]0;title\x07more";
        let s = sanitize_untrusted(evil);
        assert!(!s.contains('\x1b'), "ESC must be gone");
        assert!(!s.contains('\x07'), "BEL must be gone");
        assert!(!s.contains('\x00'), "NUL must be gone");
        // The visible letters survive as inert text.
        assert!(s.contains("ok"));
        assert!(s.contains("text"));
        assert!(s.contains("more"));
    }

    #[test]
    fn keeps_newlines_and_tabs_and_unicode() {
        let s = sanitize_untrusted("a\nb\tc — ñ 漢");
        assert_eq!(s, "a\nb\tc — ñ 漢");
    }

    #[test]
    fn fake_approval_spoof_is_neutralized() {
        // A hostile command output trying to impersonate archangelctl's
        // approval chrome and clear the screen first.
        let spoof = "\x1b[2J\x1b[H?? APPROVE? [a]pprove\nyes";
        let s = sanitize_untrusted(spoof);
        assert!(!s.contains('\x1b'));
        // The text is still visible, but as plainly part of the untrusted
        // block (no cursor move, no screen clear could have happened).
        assert!(s.contains("APPROVE?"));
    }

    #[test]
    fn untrusted_block_never_emits_escapes_from_content() {
        let p = Palette::fixed(true);
        let rendered = untrusted_block(p, Block::Output, "cmd", "\x1b[31mred\x1b[0m");
        // Our own styling adds ESC for the header/footer, but the content
        // region must contain none from the untrusted input.
        assert!(rendered.contains("red"));
        assert!(!rendered.contains("\x1b[31m"));
        assert!(!rendered.contains("\x1b[0mred"));
    }

    #[test]
    fn truncates_oversized_untrusted() {
        let big = "A".repeat(MAX_UNTRUSTED_BYTES + 5000);
        let s = sanitize_untrusted(&big);
        assert!(s.len() <= MAX_UNTRUSTED_BYTES + 128);
        assert!(s.contains("truncated"));
    }

    #[test]
    fn palette_disabled_emits_no_escapes() {
        let p = Palette::fixed(false);
        let line = trusted_line(p, Block::Error, "denied");
        assert!(!line.contains('\x1b'));
        assert!(line.contains("denied"));
    }

    #[test]
    fn palette_enabled_wraps_with_reset() {
        let p = Palette::fixed(true);
        let line = trusted_line(p, Block::Operator, "hi");
        assert!(line.starts_with("\x1b["));
        assert!(line.ends_with("\x1b[0m"));
    }
}
