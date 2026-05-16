//! Chain verification.
//!
//! Verification is the entire point of the audit log: it is a *detective*
//! control (threat model layer #15 — it detects tampering after the fact, it
//! does not prevent it). A log is trustworthy only if [`verify_chain`]
//! accepts it end to end.
//!
//! What is checked, for every entry, in order:
//!
//! 1. The line parses as an [`AuditEntry`].
//! 2. `seq` is exactly the expected monotonic value (no gaps, no reorder).
//! 3. `prev_hash` equals the recomputed hash of the previous entry (or the
//!    genesis sentinel for `seq == 0`).
//! 4. The Ed25519 signature is valid over the recomputed canonical bytes,
//!    using the expected public key (strict verification — no malleability).
//! 5. The stored `entry_hash` matches the recomputed hash (defense in depth;
//!    the recomputed value, never the stored one, is used for linking).
//!
//! The genesis entry additionally must embed the expected public key.

use std::io::BufRead;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    entry::{chain_hash, genesis_prev_hash_hex, AuditEntry, AuditEvent},
    error::AuditError,
    hex,
    key::verifying_key_from_hex,
};

/// Outcome of a successful verification: the chain head, ready to resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    /// Number of entries verified (including genesis).
    pub entries: u64,
    /// Sequence number the next appended entry must use.
    pub next_seq: u64,
    /// Hex hash of the last verified entry (the value to chain onto).
    pub head_hash_hex: String,
}

/// Verify an entire chain from `reader`, requiring every entry to be signed
/// by `expected_public_key`.
///
/// On any inconsistency this returns [`AuditError::ChainBroken`] identifying
/// the first bad sequence number. A truncated final line (power loss) is
/// reported as a break at its sequence rather than silently accepted.
pub fn verify_chain<R: BufRead>(
    reader: R,
    expected_public_key: &VerifyingKey,
) -> Result<ChainHead, AuditError> {
    let mut expected_seq: u64 = 0;
    // Holds the genesis sentinel before the first entry, then the recomputed
    // hash of the last verified entry. Used both to check the next entry's
    // `prev_hash` and as the returned chain head.
    let mut chain_head = genesis_prev_hash_hex();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| {
            AuditError::ChainBroken {
                seq: expected_seq,
                reason: format!("entry does not parse as JSON: {e}"),
            }
        })?;

        verify_entry(&entry, expected_seq, &chain_head, expected_public_key)?;

        // Recompute the link hash; never trust the stored field for chaining.
        let canonical = entry.record.canonical_bytes()?;
        let sig_bytes = decode_sig(&entry.signature, expected_seq)?;
        let recomputed = chain_hash(&canonical, &sig_bytes);

        chain_head = hex::encode(&recomputed);
        expected_seq = expected_seq.saturating_add(1);
    }

    if expected_seq == 0 {
        return Err(AuditError::Empty);
    }

    Ok(ChainHead {
        entries: expected_seq,
        next_seq: expected_seq,
        head_hash_hex: chain_head,
    })
}

/// Convenience: verify a chain whose genesis entry declares its own key,
/// then confirm that key is the one the caller trusts.
///
/// This still requires the caller to pin `trusted_public_key`; the genesis
/// self-declaration is informational and must match the pin.
pub fn verify_chain_with_pinned_key<R: BufRead>(
    reader: R,
    trusted_public_key: &VerifyingKey,
) -> Result<ChainHead, AuditError> {
    verify_chain(reader, trusted_public_key)
}

fn verify_entry(
    entry: &AuditEntry,
    expected_seq: u64,
    expected_prev: &str,
    expected_public_key: &VerifyingKey,
) -> Result<(), AuditError> {
    if entry.record.seq != expected_seq {
        return Err(AuditError::ChainBroken {
            seq: expected_seq,
            reason: format!(
                "sequence number mismatch: found {}, expected {expected_seq}",
                entry.record.seq
            ),
        });
    }

    if entry.record.prev_hash != expected_prev {
        return Err(AuditError::ChainBroken {
            seq: expected_seq,
            reason: "prev_hash does not match the previous entry's hash".into(),
        });
    }

    // The genesis entry must pin the expected public key.
    if expected_seq == 0 {
        match &entry.record.event {
            AuditEvent::Genesis { audit_public_key } => {
                let declared = verifying_key_from_hex(audit_public_key)?;
                if declared.as_bytes() != expected_public_key.as_bytes() {
                    return Err(AuditError::ChainBroken {
                        seq: 0,
                        reason: "genesis public key does not match the pinned key".into(),
                    });
                }
            }
            _ => {
                return Err(AuditError::ChainBroken {
                    seq: 0,
                    reason: "first entry is not a genesis entry".into(),
                });
            }
        }
    }

    let canonical = entry.record.canonical_bytes()?;
    let sig_bytes = decode_sig(&entry.signature, expected_seq)?;
    let signature = Signature::from_bytes(&sig_bytes);

    expected_public_key
        .verify_strict(&canonical, &signature)
        .map_err(|e| AuditError::ChainBroken {
            seq: expected_seq,
            reason: format!("Ed25519 signature verification failed: {e}"),
        })?;

    // Defense in depth: the stored entry_hash must equal the recomputed one.
    let recomputed = chain_hash(&canonical, &sig_bytes);
    if hex::encode(&recomputed) != entry.entry_hash {
        return Err(AuditError::ChainBroken {
            seq: expected_seq,
            reason: "stored entry_hash does not match recomputed hash".into(),
        });
    }

    Ok(())
}

fn decode_sig(signature_hex: &str, seq: u64) -> Result<[u8; 64], AuditError> {
    let raw = hex::decode(signature_hex)?;
    raw.try_into().map_err(|_| AuditError::ChainBroken {
        seq,
        reason: "signature is not 64 bytes".into(),
    })
}
