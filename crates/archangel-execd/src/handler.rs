//! The executor security pipeline (trust tier T2).
//!
//! This is the single place where a request becomes an execution. Order is
//! load-bearing and every gate is fail-closed. The daemon is **lower trust**
//! than this code: every field of the request is a claim to be re-verified,
//! never a fact.
//!
//! Pipeline, in strict order (first failure wins, nothing falls through):
//!
//! 1. Decode the length-prefixed envelope.
//! 2. Verify protocol version + per-session Ed25519 signature
//!    (`archangel-ipc`). Until this passes, the request bytes are hostile.
//! 3. Replay / reorder check (monotonic `seq` + nonce).
//! 4. Sanitize `exec_name` (defense-in-depth path-traversal guard) and
//!    resolve + verify the signed `.exec` bundle (`archangel-exec-format`).
//! 5. Validate supplied arguments against the bundle schema (#7).
//! 6. Enforce the v0.1 invariant: only `read_only = true` bundles run —
//!    read from the *verified bundle*, never the daemon's claim.
//! 7. Re-evaluate the immutable denylist + allowlist (#8/#9) over the
//!    bundle's own payload and declared paths (defense in depth).
//! 8. Only now, run the action in the minimal sandbox.
//!
//! Requests are processed **serially** in v0.1 — the executor is the sole
//! mutation point; serializing bounds blast rate and simplifies reasoning.

use std::{path::PathBuf, time::Duration};

use archangel_core::ActionId;
use archangel_exec_format::{OperatorTrust, VerifiedBundle};
use archangel_ipc::{ExecOutcome, ExecRequest, ExecResponse, RejectStage, SignedEnvelope};
use archangel_policy::{PathAccess, PathIntent, PolicyDecision, PolicyEngine, PolicyRequest};

use crate::{
    replay::ReplayGuard,
    sandbox::{ActionRunner, RunContext},
};

/// A rejection short-circuits the pipeline. `?` carries it straight out.
type Gate<T> = Result<T, ExecResponse>;

/// Zeroed id used when a request cannot be decoded far enough to learn its
/// real `ActionId`. The response still names *something* for the log.
const fn unknown_action() -> ActionId {
    ActionId::from_bytes([0u8; 16])
}

/// Limits applied to every sandboxed run.
#[derive(Debug, Clone, Copy)]
pub struct ExecLimits {
    /// Hard wall-clock timeout per action.
    pub timeout: Duration,
    /// Per-stream output byte cap.
    pub max_output: usize,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_output: 1024 * 1024,
        }
    }
}

/// The executor. Generic over the runner so the pipeline is tested without
/// spawning real processes.
pub struct Executor<R: ActionRunner> {
    session_key: ed25519_dalek::VerifyingKey,
    trust: OperatorTrust,
    policy: PolicyEngine,
    bundle_dir: PathBuf,
    limits: ExecLimits,
    replay: ReplayGuard,
    runner: R,
}

/// `exec_name` must be a single safe path component. Anything with a slash,
/// a NUL, a `..`, or outside `[A-Za-z0-9._-]` is refused before it can be
/// joined to the bundle directory (path-traversal defense in depth).
fn safe_exec_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl<R: ActionRunner> Executor<R> {
    /// Construct an executor.
    #[must_use]
    pub fn new(
        session_key: ed25519_dalek::VerifyingKey,
        trust: OperatorTrust,
        policy: PolicyEngine,
        bundle_dir: PathBuf,
        limits: ExecLimits,
        runner: R,
    ) -> Self {
        Self {
            session_key,
            trust,
            policy,
            bundle_dir,
            limits,
            replay: ReplayGuard::new(),
            runner,
        }
    }

    /// Run one request end to end. Never panics; never returns "allow" on
    /// any internal failure.
    pub fn handle(&mut self, frame_body: &[u8]) -> ExecResponse {
        match self.dispatch(frame_body) {
            Ok(resp) | Err(resp) => resp,
        }
    }

    /// The pipeline. Each gate returns `Err(rejection)` which `?` turns
    /// into the final response; the success path returns `Ok`.
    fn dispatch(&mut self, frame_body: &[u8]) -> Gate<ExecResponse> {
        let request = self.authenticate(frame_body)?;
        let action_id = request.action_id;
        self.anti_replay(&request)?;
        let bundle = self.resolve_bundle(&request)?;
        Self::check_args_and_read_only(&request, &bundle)?;
        self.policy_gate(&request, &bundle)?;
        Ok(Self::execute(&self.runner, self.limits, &request, &bundle, action_id))
    }

    /// Steps 1–2: decode the envelope, verify version + session signature.
    fn authenticate(&self, frame_body: &[u8]) -> Gate<ExecRequest> {
        let envelope = SignedEnvelope::from_frame_body(frame_body).map_err(|e| {
            ExecResponse::rejected(
                unknown_action(),
                RejectStage::SignatureInvalid,
                format!("malformed envelope: {e}"),
            )
        })?;
        envelope.open(&self.session_key).map_err(|e| {
            ExecResponse::rejected(
                unknown_action(),
                RejectStage::SignatureInvalid,
                format!("envelope rejected: {e}"),
            )
        })
    }

    /// Step 3: replay / reorder.
    fn anti_replay(&mut self, request: &ExecRequest) -> Gate<()> {
        self.replay
            .admit(request.session_id, request.seq, request.nonce)
            .map_err(|why| {
                ExecResponse::rejected(
                    request.action_id,
                    RejectStage::Replay,
                    format!("replay guard: {why:?}"),
                )
            })
    }

    /// Step 4: name hygiene + signed-bundle verification.
    fn resolve_bundle(&self, request: &ExecRequest) -> Gate<VerifiedBundle> {
        if !safe_exec_name(&request.exec_name) {
            return Err(ExecResponse::rejected(
                request.action_id,
                RejectStage::BundleUnverified,
                format!("unsafe exec name {:?}", request.exec_name),
            ));
        }
        let exec_path = self.bundle_dir.join(format!("{}.exec", request.exec_name));
        let sig_path = self
            .bundle_dir
            .join(format!("{}.exec.sig", request.exec_name));
        VerifiedBundle::load(&exec_path, &sig_path, &self.trust).map_err(|e| {
            ExecResponse::rejected(
                request.action_id,
                RejectStage::BundleUnverified,
                format!("bundle did not verify: {e}"),
            )
        })
    }

    /// Steps 5–6: arg schema, then the v0.1 read-only invariant (from the
    /// verified bundle, not the daemon's claim).
    fn check_args_and_read_only(
        request: &ExecRequest,
        bundle: &VerifiedBundle,
    ) -> Gate<()> {
        bundle.validate_args(&request.args).map_err(|e| {
            ExecResponse::rejected(
                request.action_id,
                RejectStage::ArgRejected,
                format!("argument rejected: {e}"),
            )
        })?;
        if bundle.manifest().meta.read_only {
            Ok(())
        } else {
            Err(ExecResponse::rejected(
                request.action_id,
                RejectStage::NotReadOnly,
                "this milestone executes read_only bundles only".to_owned(),
            ))
        }
    }

    /// Step 7: denylist + allowlist re-evaluation (defense in depth).
    fn policy_gate(&self, request: &ExecRequest, bundle: &VerifiedBundle) -> Gate<()> {
        let manifest = bundle.manifest();
        let mut intents: Vec<PathIntent<'_>> = manifest
            .sandbox
            .allowed_paths_ro
            .iter()
            .map(|p| PathIntent {
                path: p,
                access: PathAccess::Read,
            })
            .collect();
        intents.extend(manifest.sandbox.allowed_paths_rw.iter().map(|p| {
            PathIntent {
                path: p,
                access: PathAccess::Write,
            }
        }));
        let commands = [manifest.payload.inline.as_str()];
        let decision = self.policy.evaluate(&PolicyRequest {
            profile: &request.profile,
            mode: request.mode,
            exec: &request.exec_name,
            commands: &commands,
            paths: &intents,
        });
        match decision {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny {
                category, reason, ..
            } => Err(ExecResponse::rejected(
                request.action_id,
                RejectStage::DenylistHit,
                format!("denied ({category:?}): {reason}"),
            )),
            PolicyDecision::NotAllowed { reason } => Err(ExecResponse::rejected(
                request.action_id,
                RejectStage::NotAllowlisted,
                reason,
            )),
        }
    }

    /// Step 8: run in the minimal sandbox and shape the response.
    fn execute(
        runner: &R,
        limits: ExecLimits,
        request: &ExecRequest,
        bundle: &VerifiedBundle,
        action_id: ActionId,
    ) -> ExecResponse {
        let script = &bundle.manifest().payload.inline;
        let result = runner.run(&RunContext {
            script,
            args: &request.args,
            timeout: limits.timeout,
            max_output: limits.max_output,
        });
        ExecResponse {
            action_id,
            outcome: ExecOutcome::Completed {
                exit_code: result.exit_code,
                duration_ms: result.duration_ms,
                stdout: result.stdout,
                stderr: result.stderr,
                output_truncated: result.truncated,
            },
        }
    }
}
