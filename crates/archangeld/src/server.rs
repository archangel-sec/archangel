//! Control-plane socket server (trust boundary A enforcement).
//!
//! Mirrors the executor's discipline for boundary B: the request bytes are
//! hostile until proven otherwise. Order, fail-closed, per accepted
//! connection:
//!
//! 1. (socket layer, in `main`) check peer credentials.
//! 2. decode the length-prefixed envelope;
//! 3. verify protocol version + operator Ed25519 signature
//!    (`archangel-ctl`) — until this passes the bytes are not trusted;
//! 4. replay / reorder check (per-connection monotonic `seq` + nonce);
//! 5. dispatch the request to the read-only pipeline.
//!
//! Any failure becomes a `CtlResponse::Error` frame — never a panic, never
//! an unauthenticated action.

use std::collections::HashSet;

use archangel_ctl::{response_to_frame, CtlOutcome, CtlRequest, CtlResponse, SignedCtlEnvelope};
use ed25519_dalek::VerifyingKey;

use crate::orchestrator::{ExecTransport, Orchestrator, TaskOutcome};
use archangel_audit::DurableSink;
use archangel_llm::LlmBackend;

/// What the control server can ask the daemon core to do. Keeps the server
/// decoupled from the concrete orchestrator so it is unit-testable.
pub trait CtlService {
    /// Run one operator task through the read-only pipeline.
    fn run_task(
        &mut self,
        task: &str,
        context: &[(String, String)],
    ) -> impl core::future::Future<Output = CtlOutcome>;

    /// Approve a pending action (#13). `action_digest` is echoed from the
    /// `ApprovalRequired` the daemon sent and must bind the exact action.
    fn approve(
        &mut self,
        approval_id: &str,
        action_digest: &str,
    ) -> impl core::future::Future<Output = CtlOutcome>;

    /// Reject (discard) a pending action.
    fn reject(&mut self, approval_id: &str) -> CtlOutcome;

    /// Reload the signed policy (v0.1: not yet supported — honest no).
    fn reload_policy(&mut self) -> impl core::future::Future<Output = (bool, String)>;
}

fn outcome_to_ctl(o: TaskOutcome) -> CtlOutcome {
    match o {
        TaskOutcome::Asked { question } => CtlOutcome::Asked { question },
        TaskOutcome::Refused { reason } => CtlOutcome::Refused { reason },
        TaskOutcome::Denied { stage, reason } => CtlOutcome::Denied { stage, reason },
        TaskOutcome::ApprovalRequired {
            approval_id,
            action_digest,
            exec,
            reason,
            preview,
            two_person,
        } => CtlOutcome::ApprovalRequired {
            approval_id,
            action_digest,
            exec,
            reason,
            preview,
            two_person,
        },
        TaskOutcome::Compromised => CtlOutcome::Compromised,
        TaskOutcome::Executed {
            exec,
            exit_code,
            stdout,
            stderr,
        } => CtlOutcome::Executed {
            exec,
            exit_code,
            stdout,
            stderr,
        },
    }
}

// `use_self` is allowed here: the inherent `Orchestrator::run_task` must be
// named explicitly to disambiguate it from this trait's `run_task` of the
// same name — `Self::run_task` would resolve ambiguously.
#[allow(clippy::use_self)]
impl<B: LlmBackend, T: ExecTransport, S: DurableSink> CtlService for Orchestrator<B, T, S> {
    async fn run_task(&mut self, task: &str, context: &[(String, String)]) -> CtlOutcome {
        let borrowed: Vec<(&str, &str)> = context
            .iter()
            .map(|(l, c)| (l.as_str(), c.as_str()))
            .collect();
        match Orchestrator::run_task(self, task, &borrowed).await {
            Ok(o) => outcome_to_ctl(o),
            Err(e) => CtlOutcome::Denied {
                stage: "daemon".to_owned(),
                reason: format!("pipeline error: {e}"),
            },
        }
    }

    async fn approve(&mut self, approval_id: &str, action_digest: &str) -> CtlOutcome {
        match Orchestrator::approve(self, approval_id, action_digest).await {
            Ok(o) => outcome_to_ctl(o),
            Err(e) => CtlOutcome::Denied {
                stage: "daemon".to_owned(),
                reason: format!("approval error: {e}"),
            },
        }
    }

    fn reject(&mut self, approval_id: &str) -> CtlOutcome {
        outcome_to_ctl(Orchestrator::reject(self, approval_id))
    }

    async fn reload_policy(&mut self) -> (bool, String) {
        (
            false,
            "policy reload needs signed allowlists (milestone v0.3); \
             not available in this build"
                .to_owned(),
        )
    }
}

/// Per-connection replay/reorder guard for the control plane.
#[derive(Debug, Default)]
pub struct CtlReplayGuard {
    last_seq: Option<u64>,
    seen_nonces: HashSet<[u8; 16]>,
}

impl CtlReplayGuard {
    /// A fresh guard (one per accepted connection).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept iff `seq` strictly increases and `nonce` is unseen on this
    /// connection. Rejected requests do not advance state.
    pub fn admit(&mut self, seq: u64, nonce: [u8; 16]) -> Result<(), &'static str> {
        if let Some(last) = self.last_seq {
            if seq <= last {
                return Err("non-monotonic seq (replay/reorder)");
            }
        }
        if !self.seen_nonces.insert(nonce) {
            return Err("duplicate nonce (replay)");
        }
        self.last_seq = Some(seq);
        Ok(())
    }
}

fn error_frame(detail: impl Into<String>) -> Vec<u8> {
    let resp = CtlResponse::Error {
        detail: detail.into(),
    };
    // Encoding a tiny fixed response cannot realistically fail; if it
    // somehow does, send an empty frame (the client will treat a short
    // read as a transport error and not as success).
    response_to_frame(&resp).unwrap_or_default()
}

/// Handle one decoded control frame body, returning the response frame.
///
/// `operator_pub` is the pinned operator key from
/// `/etc/archangel/trust/operator.pub`. Never panics.
pub async fn handle_ctl_frame<Svc: CtlService>(
    frame_body: &[u8],
    operator_pub: &VerifyingKey,
    replay: &mut CtlReplayGuard,
    service: &mut Svc,
) -> Vec<u8> {
    let envelope = match SignedCtlEnvelope::from_frame_body(frame_body) {
        Ok(e) => e,
        Err(e) => return error_frame(format!("malformed control envelope: {e}")),
    };
    let body = match envelope.open(operator_pub) {
        Ok(b) => b,
        Err(e) => return error_frame(format!("control envelope rejected: {e}")),
    };
    if let Err(why) = replay.admit(body.seq, body.nonce) {
        return error_frame(format!("replay guard: {why}"));
    }

    let response = match body.request {
        CtlRequest::Ping => CtlResponse::Pong,
        CtlRequest::RunTask { task, context } => {
            CtlResponse::Task(service.run_task(&task, &context).await)
        }
        CtlRequest::Approve {
            approval_id,
            action_digest,
        } => CtlResponse::Task(service.approve(&approval_id, &action_digest).await),
        CtlRequest::Reject { approval_id } => CtlResponse::Task(service.reject(&approval_id)),
        CtlRequest::ReloadPolicy => {
            let (ok, detail) = service.reload_policy().await;
            CtlResponse::PolicyReloaded { ok, detail }
        }
    };
    response_to_frame(&response).unwrap_or_else(|_| error_frame("response encode failed"))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_ctl::{
        response_from_frame_body, CtlBody, CtlOutcome, CtlRequest, CtlResponse, SignedCtlEnvelope,
    };
    use ed25519_dalek::SigningKey;

    use super::{handle_ctl_frame, CtlReplayGuard, CtlService};

    struct MockService {
        ran: u32,
    }
    impl CtlService for MockService {
        async fn run_task(&mut self, task: &str, _c: &[(String, String)]) -> CtlOutcome {
            self.ran += 1;
            CtlOutcome::Refused {
                reason: format!("mock saw: {task}"),
            }
        }
        async fn approve(&mut self, id: &str, _digest: &str) -> CtlOutcome {
            CtlOutcome::Denied {
                stage: "mock".to_owned(),
                reason: format!("approve {id}"),
            }
        }
        fn reject(&mut self, id: &str) -> CtlOutcome {
            CtlOutcome::Denied {
                stage: "mock".to_owned(),
                reason: format!("reject {id}"),
            }
        }
        async fn reload_policy(&mut self) -> (bool, String) {
            (false, "nope".to_owned())
        }
    }

    fn opkey(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn frame(seq: u64, nonce: [u8; 16], req: CtlRequest, key: &SigningKey) -> Vec<u8> {
        let body = CtlBody {
            seq,
            nonce,
            issued_ms: 1,
            request: req,
        };
        let env = SignedCtlEnvelope::seal(&body, key).expect("seal");
        let f = env.to_frame().expect("frame");
        f.get(4..).expect("body").to_vec()
    }

    async fn run(body: &[u8], op_pub: &SigningKey, g: &mut CtlReplayGuard) -> CtlResponse {
        let mut svc = MockService { ran: 0 };
        let out = handle_ctl_frame(body, &op_pub.verifying_key(), g, &mut svc).await;
        response_from_frame_body(out.get(4..).expect("resp body")).expect("decode")
    }

    #[tokio::test]
    async fn valid_signed_request_is_serviced() {
        let k = opkey(1);
        let mut g = CtlReplayGuard::new();
        let body = frame(1, [1; 16], CtlRequest::Ping, &k);
        assert_eq!(run(&body, &k, &mut g).await, CtlResponse::Pong);
    }

    #[tokio::test]
    async fn foreign_operator_key_is_rejected() {
        let signer = opkey(1);
        let mut g = CtlReplayGuard::new();
        let body = frame(1, [1; 16], CtlRequest::Ping, &signer);
        // Daemon trusts a different operator key.
        let r = run(&body, &opkey(2), &mut g).await;
        assert!(matches!(r, CtlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn replayed_frame_is_rejected() {
        let k = opkey(1);
        let mut g = CtlReplayGuard::new();
        let body = frame(1, [9; 16], CtlRequest::Ping, &k);
        assert_eq!(run(&body, &k, &mut g).await, CtlResponse::Pong);
        // Byte-identical replay on the same connection guard.
        let r = run(&body, &k, &mut g).await;
        assert!(matches!(r, CtlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn non_monotonic_seq_is_rejected() {
        let k = opkey(1);
        let mut g = CtlReplayGuard::new();
        assert_eq!(
            run(&frame(5, [1; 16], CtlRequest::Ping, &k), &k, &mut g).await,
            CtlResponse::Pong
        );
        let r = run(&frame(5, [2; 16], CtlRequest::Ping, &k), &k, &mut g).await;
        assert!(matches!(r, CtlResponse::Error { .. }), "seq must increase");
    }

    #[tokio::test]
    async fn garbage_frame_is_an_error_not_a_panic() {
        let k = opkey(1);
        let mut g = CtlReplayGuard::new();
        let r = run(b"not a ctl envelope", &k, &mut g).await;
        assert!(matches!(r, CtlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn run_task_reaches_the_service() {
        let k = opkey(1);
        let mut g = CtlReplayGuard::new();
        let body = frame(
            1,
            [7; 16],
            CtlRequest::RunTask {
                task: "check disk".to_owned(),
                context: vec![],
            },
            &k,
        );
        let r = run(&body, &k, &mut g).await;
        assert!(matches!(
            r,
            CtlResponse::Task(CtlOutcome::Refused { reason }) if reason.contains("check disk")
        ));
    }
}
