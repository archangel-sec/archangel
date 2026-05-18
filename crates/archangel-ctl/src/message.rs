//! Control-plane messages (operator ↔ daemon).
//!
//! v0.1 is the read-only control surface. The operator authenticates with
//! peer credentials *and* an Ed25519 signature over every request (stricter
//! than architecture §4.1's "non-read operations only" — uniform signing is
//! simpler to reason about and fails closed).

use serde::{Deserialize, Serialize};

/// What the operator asks the daemon to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CtlRequest {
    /// Liveness check.
    Ping,
    /// Run one task through the read-only pipeline. `context` is a list of
    /// labeled **untrusted** inputs (file/log excerpts) the operator wants
    /// the model to consider; the daemon spotlights them (#2).
    RunTask {
        /// The operator's instruction (trusted as a task, not as a command).
        task: String,
        /// Labeled untrusted context: `(label, content)`.
        context: Vec<(String, String)>,
    },
    /// Ask the daemon to reload the signed allowlist/policy.
    ReloadPolicy,
}

/// The result of a task, mirrored from the orchestrator's outcome in a
/// wire-stable, serializable form (the orchestrator type lives in the
/// `archangeld` binary and must not leak across this boundary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CtlOutcome {
    /// The model asked the operator a clarifying question; nothing ran.
    Asked {
        /// The question.
        question: String,
    },
    /// The model declined; nothing ran.
    Refused {
        /// Why.
        reason: String,
    },
    /// A gate refused the proposed action; nothing ran.
    Denied {
        /// Which stage refused it.
        stage: String,
        /// Reason.
        reason: String,
    },
    /// Allowlisted, but the action needs operator approval before it can
    /// run (layers #13/#14). Nothing ran.
    ApprovalRequired {
        /// The `.exec` bundle awaiting approval.
        exec: String,
        /// Why approval is required (mode/risk).
        reason: String,
        /// Whether two independent operator signatures are required.
        two_person: bool,
    },
    /// The session was aborted (canary leak, #3).
    Compromised,
    /// The action ran on the executor.
    Executed {
        /// Tool that ran.
        exec: String,
        /// Process exit code.
        exit_code: i32,
        /// Captured stdout (already size-capped by the executor).
        stdout: String,
        /// Captured stderr.
        stderr: String,
    },
}

/// The daemon's reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum CtlResponse {
    /// Reply to [`CtlRequest::Ping`].
    Pong,
    /// Reply to [`CtlRequest::RunTask`].
    Task(CtlOutcome),
    /// Reply to [`CtlRequest::ReloadPolicy`].
    PolicyReloaded {
        /// Whether the reload succeeded.
        ok: bool,
        /// Human-readable detail.
        detail: String,
    },
    /// The daemon could not service the request (not a policy denial —
    /// those are a `Task(Denied{..})`).
    Error {
        /// What went wrong.
        detail: String,
    },
}
