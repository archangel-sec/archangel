//! Render a [`CtlResponse`] for the operator, safely.
//!
//! Every field that originated from the model or a command (questions,
//! reasons, stdout/stderr) is untrusted and is shown via the sanitizing
//! [`render::untrusted_block`] / sanitized text — it can never emit
//! terminal escapes to spoof archangelctl's own chrome. Structural,
//! daemon-produced strings (the exec name, the stage label) are short and
//! shown as trusted chrome.

use archangel_ctl::{CtlOutcome, CtlResponse};

use crate::render::{sanitize_untrusted, trusted_line, untrusted_block, Block, Palette};

/// Render a control response into a string ready to print.
#[must_use]
pub fn render_response(palette: Palette, resp: &CtlResponse) -> String {
    match resp {
        CtlResponse::Pong => trusted_line(palette, Block::Status, "pong"),
        CtlResponse::PolicyReloaded { ok, detail } => trusted_line(
            palette,
            if *ok { Block::Status } else { Block::Error },
            &format!(
                "policy reload {}: {}",
                if *ok { "ok" } else { "refused" },
                sanitize_untrusted(detail)
            ),
        ),
        CtlResponse::Error { detail } => trusted_line(
            palette,
            Block::Error,
            &format!("daemon error: {}", sanitize_untrusted(detail)),
        ),
        CtlResponse::Task(outcome) => render_outcome(palette, outcome),
    }
}

fn render_outcome(palette: Palette, outcome: &CtlOutcome) -> String {
    match outcome {
        CtlOutcome::Asked { question } => trusted_line(
            palette,
            Block::Status,
            &format!("the model asks: {}", sanitize_untrusted(question)),
        ),
        CtlOutcome::Refused { reason } => trusted_line(
            palette,
            Block::Status,
            &format!("declined: {}", sanitize_untrusted(reason)),
        ),
        CtlOutcome::Denied { stage, reason } => trusted_line(
            palette,
            Block::Error,
            &format!(
                "denied at {}: {}",
                sanitize_untrusted(stage),
                sanitize_untrusted(reason)
            ),
        ),
        CtlOutcome::ApprovalRequired {
            approval_id,
            action_digest,
            exec,
            reason,
            preview,
            two_person,
        } => {
            // The header + the `/approve`/`/reject` lines are trusted
            // chrome; the model/bundle-derived preview is untrusted and
            // shown via the sanitizing block so it cannot spoof the prompt.
            let header = trusted_line(
                palette,
                Block::Approval,
                &format!(
                    "APPROVAL REQUIRED — {}: {}{}",
                    sanitize_untrusted(exec),
                    sanitize_untrusted(reason),
                    if *two_person {
                        " [TWO-PERSON RULE]"
                    } else {
                        ""
                    }
                ),
            );
            let body = untrusted_block(palette, Block::Proposal, "will run", preview);
            let prompt = trusted_line(
                palette,
                Block::Approval,
                &format!("/approve {approval_id} {action_digest}   |   /reject {approval_id}"),
            );
            format!("{header}\n{body}\n{prompt}")
        }
        CtlOutcome::Compromised => trusted_line(
            palette,
            Block::Error,
            "session aborted: the model leaked the canary (#3) — \
             treat this session as compromised and review the audit log",
        ),
        CtlOutcome::Executed {
            exec,
            exit_code,
            stdout,
            stderr,
        } => {
            let header = trusted_line(
                palette,
                Block::Proposal,
                &format!("{} ran (exit {})", sanitize_untrusted(exec), exit_code),
            );
            let mut out = header;
            if !stdout.is_empty() {
                out.push('\n');
                out.push_str(&untrusted_block(palette, Block::Output, "stdout", stdout));
            }
            if !stderr.is_empty() {
                out.push('\n');
                out.push_str(&untrusted_block(palette, Block::Output, "stderr", stderr));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use archangel_ctl::{CtlOutcome, CtlResponse};

    use crate::render::Palette;

    use super::render_response;

    #[test]
    fn executed_output_is_sanitized() {
        let r = CtlResponse::Task(CtlOutcome::Executed {
            exec: "read-logs".to_owned(),
            exit_code: 0,
            stdout: "line1\x1b[2J\x1b[1;1Hline2".to_owned(),
            stderr: String::new(),
        });
        let s = render_response(Palette::fixed(false), &r);
        assert!(!s.contains('\x1b'), "command output must not emit escapes");
        assert!(s.contains("line1"));
        assert!(s.contains("line2"));
    }

    #[test]
    fn denied_reason_cannot_spoof_chrome() {
        let r = CtlResponse::Task(CtlOutcome::Denied {
            stage: "policy".to_owned(),
            reason: "\x1b[2K?? [a]pprove fake".to_owned(),
        });
        let s = render_response(Palette::fixed(false), &r);
        assert!(!s.contains('\x1b'));
        assert!(s.contains("denied at policy"));
    }

    #[test]
    fn compromised_is_loud() {
        let s = render_response(
            Palette::fixed(false),
            &CtlResponse::Task(CtlOutcome::Compromised),
        );
        assert!(s.contains("compromised"));
    }

    #[test]
    fn pong_renders() {
        assert!(render_response(Palette::fixed(false), &CtlResponse::Pong).contains("pong"));
    }
}
