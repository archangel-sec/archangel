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
use archangel_exec_format::{NetworkPolicy, OperatorTrust, VerifiedBundle};
use archangel_ipc::{ExecOutcome, ExecRequest, ExecResponse, RejectStage, SignedEnvelope};
use archangel_policy::{PathAccess, PathIntent, PolicyDecision, PolicyEngine, PolicyRequest};
use archangel_sandbox::{NetworkMode, SandboxPlan, SandboxPolicy};
use archangel_snapshot::Snapshotter;

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
    /// Snapshot backend (#16). `None` ⇒ any `mutates_persistent_state`
    /// action is refused fail-closed (no recovery point ⇒ no mutation).
    snapshotter: Option<Box<dyn Snapshotter>>,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_key: ed25519_dalek::VerifyingKey,
        trust: OperatorTrust,
        policy: PolicyEngine,
        bundle_dir: PathBuf,
        limits: ExecLimits,
        runner: R,
        snapshotter: Option<Box<dyn Snapshotter>>,
    ) -> Self {
        Self {
            session_key,
            trust,
            policy,
            bundle_dir,
            limits,
            replay: ReplayGuard::new(),
            runner,
            snapshotter,
        }
    }

    /// Replace the trusted per-session verifying key.
    ///
    /// `archangeld` rotates its session key on every restart and publishes
    /// the public half to a file; the socket server calls this before each
    /// connection so a daemon restart is picked up without restarting the
    /// executor. The replay guard is keyed by `SessionId`, so a new
    /// session naturally gets fresh replay state.
    pub const fn set_session_key(&mut self, key: ed25519_dalek::VerifyingKey) {
        self.session_key = key;
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
        // #16: no mutation without a recovery point (fail-closed).
        let snapshot_id = self.snapshot_gate(&request, &bundle)?;
        // #11: build the enforceable sandbox from the verified manifest.
        // No plan ⇒ no run (fail-closed).
        let plan = Self::sandbox_gate(&request, &bundle)?;
        Ok(Self::execute(
            &self.runner,
            self.limits,
            &request,
            &bundle,
            action_id,
            snapshot_id,
            &plan,
        ))
    }

    /// Step 7.6 (#11): translate the *verified* bundle's `[sandbox]`
    /// section into an enforceable [`SandboxPlan`]. Every fail-closed
    /// check (unknown seccomp profile / capability, invalid limit, bad
    /// path) lives in `archangel-sandbox`; here we only map the manifest
    /// types and convert any error into a rejection. A bundle that cannot
    /// produce a plan never runs.
    fn sandbox_gate(
        request: &ExecRequest,
        bundle: &VerifiedBundle,
    ) -> Gate<SandboxPlan> {
        let reject = |msg: String| {
            ExecResponse::rejected(
                request.action_id,
                RejectStage::SandboxRejected,
                msg,
            )
        };
        let s = &bundle.manifest().sandbox;
        // `NetworkPolicy` is `#[non_exhaustive]`: an unrecognized future
        // variant is refused, never silently downgraded to a safer-looking
        // mode (fail-closed).
        let network = match s.network {
            NetworkPolicy::None => NetworkMode::None,
            NetworkPolicy::Loopback => NetworkMode::Loopback,
            NetworkPolicy::Egress => NetworkMode::Egress,
            other => {
                return Err(reject(format!(
                    "unsupported network policy {other:?}"
                )))
            }
        };
        let policy = SandboxPolicy {
            syscall_profile: s.syscall_profile.clone(),
            capabilities: s.capabilities.clone(),
            allowed_paths_ro: s.allowed_paths_ro.clone(),
            allowed_paths_rw: s.allowed_paths_rw.clone(),
            network,
            cpu_max: s.cpu_max.clone(),
            memory_max: s.memory_max.clone(),
        };
        policy
            .plan()
            .map_err(|e| reject(format!("sandbox plan refused: {e}")))
    }

    /// Step 7.5 (#16): if the verified bundle mutates persistent state, a
    /// recovery point MUST be created before it runs. No snapshot backend,
    /// no declared rw paths, or a failed snapshot ⇒ refuse. Read-only /
    /// non-mutating actions return `Ok(None)` and do nothing.
    ///
    /// (Currently shadowed by the read-only gate above; in place and
    /// independently tested so it holds the instant mutation is enabled.)
    pub(crate) fn snapshot_gate(
        &self,
        request: &ExecRequest,
        bundle: &VerifiedBundle,
    ) -> Gate<Option<String>> {
        if !bundle.manifest().meta.mutates_persistent_state {
            return Ok(None);
        }
        let reject = |reason: String| {
            ExecResponse::rejected(
                request.action_id,
                RejectStage::SnapshotUnavailable,
                reason,
            )
        };
        let target = bundle
            .manifest()
            .sandbox
            .allowed_paths_rw
            .first()
            .ok_or_else(|| {
                reject(
                    "mutating action declares no rw path to snapshot".to_owned(),
                )
            })?;
        let snap = self.snapshotter.as_ref().ok_or_else(|| {
            reject(
                "action mutates persistent state but no snapshot backend \
                 is available (no recovery point ⇒ refused)"
                    .to_owned(),
            )
        })?;
        match snap.snapshot(std::path::Path::new(target)) {
            Ok(id) => Ok(Some(id.0)),
            Err(e) => Err(reject(format!("snapshot failed: {e}"))),
        }
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
            risk: manifest.meta.risk,
            commands: &commands,
            paths: &intents,
        });
        match decision {
            // Approval (#13/#14) is a TRUST-TIER-T3 control, enforced by
            // the daemon's orchestrator before it ever signs/dispatches a
            // request. T2's job at this boundary is denylist + allowlist +
            // signed-bundle + read-only + sandbox — those are what contain
            // a *compromised* daemon (a T3 breach can still only run
            // operator-signed, denylisted-checked bundles). The executor
            // has no approval channel, so it does not (cannot) re-derive
            // the approval decision; `RequireApproval` here means
            // "allowlisted, gated upstream" and is passed. (A future
            // operator-signed approval token verifiable at T2 is tracked
            // as later hardening.)
            PolicyDecision::Allow | PolicyDecision::RequireApproval { .. } => Ok(()),
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

    /// Step 8: run the action under the layer-#11 sandbox and shape the
    /// response.
    fn execute(
        runner: &R,
        limits: ExecLimits,
        request: &ExecRequest,
        bundle: &VerifiedBundle,
        action_id: ActionId,
        snapshot_id: Option<String>,
        plan: &SandboxPlan,
    ) -> ExecResponse {
        let script = &bundle.manifest().payload.inline;
        let result = runner.run(&RunContext {
            script,
            args: &request.args,
            timeout: limits.timeout,
            max_output: limits.max_output,
            sandbox: Some(plan),
        });
        ExecResponse {
            action_id,
            outcome: ExecOutcome::Completed {
                exit_code: result.exit_code,
                duration_ms: result.duration_ms,
                stdout: result.stdout,
                stderr: result.stderr,
                output_truncated: result.truncated,
                snapshot_id,
            },
        }
    }
}
