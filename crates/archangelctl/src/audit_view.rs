//! Verify and display an audit log.
//!
//! Two jobs, in order:
//!
//! 1. **Verify** the hash chain + signatures against an operator-pinned
//!    public key (`archangel-audit`). The verdict is shown prominently:
//!    an operator must never mistake an unverified log for a trustworthy
//!    one, so verification runs first and its result frames everything.
//! 2. **Display** entries. Structural fields (seq, timestamp) come from the
//!    verified chain; the event payload contains model-influenced strings
//!    (reasons, notes), so it is passed through [`render::sanitize_untrusted`]
//!    before printing — a log line must not be able to spoof the terminal.

use std::io::Cursor;

use archangel_audit::{verify_chain, verifying_key_from_hex, AuditEntry};

use crate::render::{sanitize_untrusted, trusted_line, Block, Palette};

/// Verify `log_bytes` against `pinned_pub_hex` and render a human view.
#[must_use]
pub fn verify_and_render(log_bytes: &[u8], pinned_pub_hex: &str, palette: Palette) -> String {
    let vk = match verifying_key_from_hex(pinned_pub_hex.trim()) {
        Ok(k) => k,
        Err(e) => {
            return trusted_line(
                palette,
                Block::Error,
                &format!("invalid pinned audit public key: {e}"),
            );
        }
    };

    let mut out = String::new();
    match verify_chain(Cursor::new(log_bytes), &vk) {
        Ok(head) => {
            out.push_str(&trusted_line(
                palette,
                Block::Status,
                &format!(
                    "AUDIT CHAIN VERIFIED — {} entries, head {}",
                    head.entries, head.head_hash_hex
                ),
            ));
        }
        Err(e) => {
            out.push_str(&trusted_line(
                palette,
                Block::Error,
                &format!("AUDIT CHAIN FAILED VERIFICATION: {e}"),
            ));
            out.push_str("\n(entries below are shown for forensics and must NOT be trusted)\n");
        }
    }
    out.push('\n');

    for (n, line) in log_bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let rendered = match serde_json::from_slice::<AuditEntry>(line) {
            Ok(entry) => {
                let kind = serde_json::to_value(&entry.record.event)
                    .ok()
                    .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned());
                let payload = serde_json::to_string(&entry.record.event).unwrap_or_default();
                trusted_line(
                    palette,
                    Block::Status,
                    &format!(
                        "#{:<4} {:<18} {}",
                        entry.record.seq,
                        kind,
                        sanitize_untrusted(&payload)
                    ),
                )
            }
            Err(e) => trusted_line(
                palette,
                Block::Error,
                &format!("line {n}: unparsable audit entry: {e}"),
            ),
        };
        out.push_str(&rendered);
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_audit::{AuditEvent, AuditKeypair, AuditLog};

    use crate::render::Palette;

    use super::verify_and_render;

    fn sample_log() -> (Vec<u8>, String) {
        let kp = AuditKeypair::generate();
        let pub_hex = kp.public_hex();
        let seed: [u8; 32] = kp.secret_bytes().expose_secret().try_into().expect("seed");
        let mut buf = Vec::new();
        {
            let mut log =
                AuditLog::with_sink(&mut buf, AuditKeypair::from_secret_bytes(&seed)).expect("log");
            log.append(AuditEvent::Note {
                message: "daemon started".to_owned(),
            })
            .expect("note");
        }
        (buf, pub_hex)
    }

    #[test]
    fn valid_log_is_reported_verified() {
        let (buf, pk) = sample_log();
        let out = verify_and_render(&buf, &pk, Palette::fixed(false));
        assert!(out.contains("AUDIT CHAIN VERIFIED"));
        assert!(out.contains("daemon started"));
    }

    #[test]
    fn tampered_log_is_reported_failed() {
        let (mut buf, pk) = sample_log();
        let i = buf.len().checked_div(2).unwrap_or(0);
        if let Some(b) = buf.get_mut(i) {
            *b ^= 0xff;
        }
        let out = verify_and_render(&buf, &pk, Palette::fixed(false));
        assert!(out.contains("FAILED VERIFICATION"));
    }

    #[test]
    fn wrong_pinned_key_fails() {
        let (buf, _pk) = sample_log();
        let other = AuditKeypair::generate().public_hex();
        let out = verify_and_render(&buf, &other, Palette::fixed(false));
        assert!(out.contains("FAILED VERIFICATION"));
    }

    #[test]
    fn audit_event_text_cannot_spoof_terminal() {
        // A note whose message tries to inject ANSI must be neutralized.
        let kp = AuditKeypair::generate();
        let pub_hex = kp.public_hex();
        let seed: [u8; 32] = kp.secret_bytes().expose_secret().try_into().expect("seed");
        let mut buf = Vec::new();
        {
            let mut log =
                AuditLog::with_sink(&mut buf, AuditKeypair::from_secret_bytes(&seed)).expect("log");
            log.append(AuditEvent::Note {
                message: "evil\u{1b}[2J\u{1b}[1;1H[ APPROVED ]".to_owned(),
            })
            .expect("note");
        }
        let out = verify_and_render(&buf, &pub_hex, Palette::fixed(false));
        assert!(!out.contains('\u{1b}'), "no ESC may reach the terminal");
        assert!(out.contains("APPROVED"), "text still shown, but inert");
    }
}
