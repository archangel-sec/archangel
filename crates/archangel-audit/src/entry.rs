//! Audit entries, the hash chain, and the canonicalization rules that make
//! the chain and signatures meaningful.
//!
//! # Security invariant: deterministic canonical bytes
//!
//! The bytes that get signed and hashed are produced by
//! `serde_json::to_vec(&AuditRecord)`. This is sound **only because**
//! `AuditRecord` and every type it contains serialize deterministically:
//!
//! - All fields are structs/enums with a fixed declaration order (serde_json
//!   emits struct fields in declaration order).
//! - No `HashMap`/`HashSet` and no floating-point values appear anywhere in
//!   the record (those have non-deterministic or lossy encodings).
//! - Large or sensitive payloads (prompts, model output, command output,
//!   argument blobs) are stored as their SHA-256 **hash**, never raw. This
//!   keeps the log bounded, avoids duplicating secrets into a lower-
//!   confidentiality asset, and still binds the content into the signed
//!   chain so any change is tamper-evident.
//!
//! If you add a variant or field, preserve these properties or the entire
//! integrity guarantee (threat model layer #15) is void.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use archangel_core::{ActionId, OperationMode, SessionId};

use crate::{error::AuditError, hex, key::AuditKeypair};

/// All-zero genesis predecessor hash (no entry precedes the genesis entry).
const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// The policy decision recorded for a proposed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Action permitted by denylist + allowlist/policy.
    Allow,
    /// Action rejected. This decision is final for that action.
    Deny,
    /// Action permitted only after explicit operator approval.
    RequireApproval,
}

/// A single recorded event in the life of the daemon.
///
/// Bulk content is referenced by SHA-256 (`*_sha256` fields) rather than
/// embedded — see the module-level security invariant for the rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// First entry of every log. Anchors the chain to a specific audit key.
    Genesis {
        /// Hex-encoded Ed25519 public key that must sign every entry.
        audit_public_key: String,
    },
    /// A new operator session began.
    SessionStarted {
        /// Session identifier.
        session_id: SessionId,
        /// Operating mode selected for the session.
        mode: OperationMode,
        /// Name of the profile in effect.
        profile: String,
    },
    /// A session ended (normally or by panic/kill-switch).
    SessionEnded {
        /// Session identifier.
        session_id: SessionId,
        /// Reason the session ended.
        reason: String,
    },
    /// A prompt was sent to the LLM backend.
    LlmRequest {
        /// Session identifier.
        session_id: SessionId,
        /// Backend name (e.g. `anthropic`, `ollama`).
        backend: String,
        /// Model identifier.
        model: String,
        /// SHA-256 of the exact prompt bytes that were sent.
        prompt_sha256: String,
    },
    /// The LLM backend returned a response.
    LlmResponse {
        /// Session identifier.
        session_id: SessionId,
        /// SHA-256 of the exact response bytes that were received.
        response_sha256: String,
        /// Whether a canary token (#3) leaked into the response.
        canary_triggered: bool,
    },
    /// Policy was evaluated for a proposed action.
    PolicyDecision {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// The `.exec` bundle name the action resolved to.
        exec: String,
        /// The decision reached.
        decision: Decision,
        /// Human-readable justification (which layer/rule decided).
        reason: String,
    },
    /// An operator (or second approver) granted approval for an action.
    ApprovalGranted {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// Identity of the approver (key id / operator name).
        approver: String,
    },
    /// An execution request was dispatched to the executor.
    ExecRequested {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// The `.exec` bundle name.
        exec: String,
        /// SHA-256 of the canonical argument blob.
        args_sha256: String,
    },
    /// An execution finished.
    ExecCompleted {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// Process exit code (`-1` if killed by signal/timeout).
        exit_code: i32,
        /// Wall-clock duration in milliseconds.
        duration_ms: u64,
        /// SHA-256 of captured stdout.
        stdout_sha256: String,
        /// SHA-256 of captured stderr.
        stderr_sha256: String,
    },
    /// A filesystem snapshot was taken before a mutating action.
    SnapshotTaken {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// Opaque snapshot identifier (filesystem-specific).
        snapshot_id: String,
    },
    /// A snapshot was rolled back after a failed action.
    RollbackPerformed {
        /// Session identifier.
        session_id: SessionId,
        /// Action identifier.
        action_id: ActionId,
        /// Snapshot that was restored.
        snapshot_id: String,
    },
    /// A free-form operational note (startup, config reload, panic, etc.).
    Note {
        /// The message.
        message: String,
    },
}

/// The signed, hashed portion of an audit entry.
///
/// Field order here is load-bearing: it defines the canonical byte string.
/// Do not reorder fields without understanding the consequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonic sequence number. The genesis entry is `0`.
    pub seq: u64,
    /// Milliseconds since the Unix epoch when the entry was created.
    pub timestamp_ms: u64,
    /// Hex SHA-256 of the previous entry (64 zeros for genesis).
    pub prev_hash: String,
    /// The event being recorded.
    pub event: AuditEvent,
}

impl AuditRecord {
    /// The exact bytes that are signed and fed into the hash chain.
    ///
    /// Determinism of this function is the foundation of the entire
    /// tamper-evidence guarantee — see the module docs.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// A complete audit entry: the record plus its signature, ready to write
/// as one JSON line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The signed/hashed record.
    pub record: AuditRecord,
    /// Hex Ed25519 signature over `record.canonical_bytes()`.
    pub signature: String,
    /// Hex SHA-256 over `canonical_bytes ++ signature_bytes`.
    ///
    /// Stored for convenience and human inspection only. Verification always
    /// **recomputes** this value and never trusts the stored field.
    pub entry_hash: String,
}

/// Compute the chain hash for an entry: `SHA-256(canonical ++ signature)`.
///
/// Binding the signature into the hash prevents an attacker from swapping a
/// validly-signed record's signature for another.
pub(crate) fn chain_hash(canonical: &[u8], signature: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hasher.update(signature);
    hasher.finalize().into()
}

/// SHA-256 of arbitrary content, hex-encoded. Helper for callers that need
/// to record a `*_sha256` field.
#[must_use]
pub fn sha256_hex(content: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(content).into();
    hex::encode(&digest)
}

/// Hex of the genesis predecessor hash (all zeros).
#[must_use]
pub(crate) fn genesis_prev_hash_hex() -> String {
    hex::encode(&GENESIS_PREV_HASH)
}

/// Build a signed [`AuditEntry`] from a record and a keypair.
pub(crate) fn seal(
    record: AuditRecord,
    keypair: &AuditKeypair,
) -> Result<(AuditEntry, [u8; 32]), AuditError> {
    let canonical = record.canonical_bytes()?;
    let signature = keypair.sign(&canonical);
    let entry_hash = chain_hash(&canonical, &signature);
    let entry = AuditEntry {
        record,
        signature: hex::encode(&signature),
        entry_hash: hex::encode(&entry_hash),
    };
    Ok((entry, entry_hash))
}
