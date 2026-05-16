//! Hash-chained, signed, append-only audit log.
//!
//! Implements layer #15 of the threat model. Asset A3 ("audit log") has
//! **CRITICAL integrity** and only LOW confidentiality: the log must be
//! impossible to alter undetectably, but its contents are not themselves
//! secret.
//!
//! Every entry:
//!
//! - carries a monotonic sequence number,
//! - embeds the SHA-256 of the previous entry (a Merkle-style chain),
//! - is signed with the daemon's Ed25519 audit key,
//! - and binds its own signature into its chain hash so signatures cannot
//!   be transplanted between records.
//!
//! Tampering with, reordering, truncating, or re-signing any entry makes
//! [`verify_chain`] fail at the first offending sequence number. This is a
//! *detective* control: it does not prevent tampering, it makes tampering
//! undeniable after the fact.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Audit subsystem error types.
pub mod error;
mod hex;
/// Audit entries, events, and the canonicalization rules.
pub mod entry;
/// Ed25519 key handling.
pub mod key;
/// The append-only log writer.
pub mod log;
/// Chain verification.
pub mod verify;

pub use entry::{sha256_hex, AuditEntry, AuditEvent, AuditRecord, Decision};
pub use error::AuditError;
pub use key::{verifying_key_from_hex, AuditKeypair};
pub use log::{AuditLog, DurableSink};
pub use verify::{verify_chain, verify_chain_with_pinned_key, ChainHead};

// Allow `&mut Vec<u8>` as a sink so tests (and callers) can inspect the
// buffer after the log is dropped.
impl DurableSink for &mut Vec<u8> {
    fn commit_line(&mut self, line: &[u8]) -> Result<(), AuditError> {
        self.extend_from_slice(line);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::io::Cursor;

    use archangel_core::{ActionId, OperationMode, SessionId};

    use super::{verify_chain, AuditEvent, AuditKeypair, AuditLog, Decision};

    /// Build a second keypair handle from an existing one (same secret seed),
    /// so a test can both write with the key and verify with its public half.
    fn clone_keypair(kp: &AuditKeypair) -> AuditKeypair {
        let secret = kp.secret_bytes();
        let seed: [u8; 32] = secret
            .expose_secret()
            .try_into()
            .expect("ed25519 seed is 32 bytes");
        AuditKeypair::from_secret_bytes(&seed)
    }

    fn write_sample_log() -> (Vec<u8>, AuditKeypair) {
        let keypair = AuditKeypair::generate();
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut log = AuditLog::with_sink(&mut buf, clone_keypair(&keypair))
                .expect("create log");
            let session = SessionId::new();
            let action = ActionId::new();
            log.append(AuditEvent::SessionStarted {
                session_id: session,
                mode: OperationMode::ReadOnly,
                profile: "default".into(),
            })
            .expect("session started");
            log.append(AuditEvent::PolicyDecision {
                session_id: session,
                action_id: action,
                exec: "list-services".into(),
                decision: Decision::Allow,
                reason: "allowlisted in read-only profile".into(),
            })
            .expect("policy decision");
            log.session_ended(session, "operator disconnected")
                .expect("session ended");
        }
        (buf, keypair)
    }

    #[test]
    fn fresh_log_has_genesis_only() {
        let keypair = AuditKeypair::generate();
        let mut buf: Vec<u8> = Vec::new();
        {
            AuditLog::with_sink(&mut buf, clone_keypair(&keypair)).expect("create");
        }
        let head = verify_chain(Cursor::new(&buf), &keypair.verifying_key())
            .expect("verify genesis-only chain");
        assert_eq!(head.entries, 1);
        assert_eq!(head.next_seq, 1);
    }

    #[test]
    fn full_chain_verifies() {
        let (buf, keypair) = write_sample_log();
        let head = verify_chain(Cursor::new(&buf), &keypair.verifying_key())
            .expect("verify full chain");
        // genesis + session_started + policy_decision + session_ended
        assert_eq!(head.entries, 4);
        assert_eq!(head.next_seq, 4);
        assert_eq!(head.head_hash_hex.len(), 64);
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let (buf, _keypair) = write_sample_log();
        let attacker = AuditKeypair::generate();
        let result = verify_chain(Cursor::new(&buf), &attacker.verifying_key());
        assert!(result.is_err(), "chain must not verify under a foreign key");
    }

    #[test]
    fn flipped_byte_breaks_chain() {
        let (mut buf, keypair) = write_sample_log();
        // Flip a byte near the end — inside the last entry, well past genesis.
        let idx = buf.len().saturating_sub(8);
        if let Some(b) = buf.get_mut(idx) {
            *b ^= 0xff;
        }
        let result = verify_chain(Cursor::new(&buf), &keypair.verifying_key());
        assert!(result.is_err(), "a single flipped byte must break the chain");
    }

    #[test]
    fn valid_prefix_is_a_valid_chain() {
        let (buf, keypair) = write_sample_log();
        let text = String::from_utf8(buf).expect("utf8");
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop(); // drop the last (session_ended) entry
        let truncated = lines.join("\n");
        let head = verify_chain(Cursor::new(truncated.as_bytes()), &keypair.verifying_key())
            .expect("a valid prefix of a chain is itself a valid chain");
        assert_eq!(head.entries, 3);
    }

    #[test]
    fn reordering_entries_breaks_chain() {
        let (buf, keypair) = write_sample_log();
        let text = String::from_utf8(buf).expect("utf8");
        let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
        lines.swap(1, 2);
        let reordered = lines.join("\n");
        let result =
            verify_chain(Cursor::new(reordered.as_bytes()), &keypair.verifying_key());
        assert!(result.is_err(), "reordering must break the chain");
    }

    #[test]
    fn empty_log_is_an_error() {
        let keypair = AuditKeypair::generate();
        let empty: &[u8] = b"";
        let result = verify_chain(Cursor::new(empty), &keypair.verifying_key());
        assert!(result.is_err(), "an empty log has no genesis entry");
    }

    #[test]
    fn keypair_seed_round_trips() {
        let kp = AuditKeypair::generate();
        let restored = AuditKeypair::from_secret_hex(&super::hex::encode(
            kp.secret_bytes().expose_secret(),
        ))
        .expect("restore from hex seed");
        assert_eq!(kp.public_hex(), restored.public_hex());
    }
}
