//! The messages that cross trust boundary B.
//!
//! `ExecRequest` is what the daemon (T3) asks the executor (T2) to do.
//! The executor treats every field as a *claim* to be re-verified, not a
//! fact to be trusted — the daemon is explicitly lower-trust than the
//! executor. The request is signed (see [`crate::envelope`]); the fields
//! here additionally carry the daemon's own claims (declared risk /
//! read-only) which the executor cross-checks against the signed `.exec`
//! bundle itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use archangel_core::{ActionId, OperationMode, RiskLevel, SessionId};

/// A request to execute one resolved action.
///
/// `BTreeMap` (not `HashMap`) for `args` keeps serialization deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Session this request belongs to.
    pub session_id: SessionId,
    /// Unique id for this action (links audit + journal).
    pub action_id: ActionId,
    /// Per-session monotonic counter. The executor rejects any request
    /// whose `seq` is not strictly greater than the last accepted one for
    /// `session_id` (replay / reorder protection).
    pub seq: u64,
    /// Per-request random nonce (defense in depth alongside `seq`).
    pub nonce: [u8; 16],
    /// Milliseconds since the Unix epoch when the daemon issued this.
    pub issued_ms: u64,
    /// Active profile name (re-checked against the allowlist by the executor).
    pub profile: String,
    /// Active operating mode.
    pub mode: OperationMode,
    /// The `.exec` bundle name to resolve and run.
    pub exec_name: String,
    /// Validated argument values (deterministic order).
    pub args: BTreeMap<String, String>,
    /// Risk the daemon believes this action has. The executor re-derives
    /// this from the signed bundle and does not trust this field blindly.
    pub declared_risk: RiskLevel,
    /// Whether the daemon believes this action is read-only. Same caveat:
    /// the executor enforces read-only from the *bundle*, not this claim.
    pub declared_read_only: bool,
}

/// Why the executor refused a request, by pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RejectStage {
    /// Peer process credentials did not match the configured daemon uid.
    PeerUnauthorized,
    /// Session signature invalid or wrong version.
    SignatureInvalid,
    /// Replay / out-of-order / duplicate nonce.
    Replay,
    /// The `.exec` bundle signature/hash/args did not verify.
    BundleUnverified,
    /// The immutable denylist matched.
    DenylistHit,
    /// Not present in the active allowlist.
    NotAllowlisted,
    /// Allowlisted but requires operator approval (#13/#14) that was not
    /// presented to the executor.
    ApprovalRequired,
    /// Argument schema validation failed.
    ArgRejected,
    /// This milestone executes read-only bundles only; this one mutates.
    NotReadOnly,
    /// The action process failed to spawn, timed out, or was killed.
    ExecFailure,
}

/// The result of (attempting) an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ExecOutcome {
    /// The action ran to completion (any exit code).
    Completed {
        /// Process exit code (`-1` if terminated by signal).
        exit_code: i32,
        /// Wall-clock duration in milliseconds.
        duration_ms: u64,
        /// Captured stdout (possibly truncated — see `output_truncated`).
        stdout: String,
        /// Captured stderr (possibly truncated — see `output_truncated`).
        stderr: String,
        /// Whether stdout/stderr was truncated at the size cap.
        output_truncated: bool,
    },
    /// The request was refused before/at execution.
    Rejected {
        /// Which gate refused it.
        stage: RejectStage,
        /// Human-readable reason (for the audit log).
        reason: String,
    },
}

/// The executor's reply for one `ExecRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResponse {
    /// Echoes the request's action id.
    pub action_id: ActionId,
    /// The outcome.
    pub outcome: ExecOutcome,
}

impl ExecResponse {
    /// Build a rejection response.
    #[must_use]
    pub fn rejected(
        action_id: ActionId,
        stage: RejectStage,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            outcome: ExecOutcome::Rejected {
                stage,
                reason: reason.into(),
            },
        }
    }
}
