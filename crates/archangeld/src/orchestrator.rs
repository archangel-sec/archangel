//! The read-only orchestration pipeline (trust tier T3).
//!
//! This is the glue that turns an operator task into, at most, one
//! pre-approved, policy-checked, signed, audited action — without ever
//! mutating the system itself (that is the executor's job across boundary
//! B). It composes every defense layer built so far in strict order and
//! records the full decision chain to the hash-chained audit log (#15) so a
//! session can be reconstructed after the fact.
//!
//! Order (fail-closed; first stop wins):
//! 1. build the defended prompt (#1–#4) and audit the LLM request;
//! 2. call the backend (a dumb pipe);
//! 3. canary check (#3) — a leak aborts the session immediately;
//! 4. strict bounded parse (#5);
//! 5. for an `invoke`: verify the signed bundle (#6/#7), re-evaluate
//!    denylist+allowlist (#8/#9), sign the `ExecRequest` (boundary B),
//!    hand it to the executor, and audit the outcome.
//!
//! Generic over the backend, the executor transport, and the audit sink so
//! the whole spine is exercised end to end in tests with no sockets.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use archangel_audit::{sha256_hex, AuditEvent, AuditKeypair, AuditLog, Decision, DurableSink};
use archangel_exec_format::{OperatorTrust, VerifiedBundle};
use archangel_ipc::{ExecOutcome, ExecResponse};
use archangel_llm::{CompletionResponse, LlmBackend, LlmError};
use archangel_policy::{PathAccess, PathIntent, PolicyDecision, PolicyEngine, PolicyRequest};

use crate::{
    prompt::{PromptBuilder, SessionSecrets, ToolSpec},
    response::{parse_model_response, ModelAction, ResponseError},
    session::Session,
};

/// How `archangeld` reaches `archangel-execd` (a Unix socket in production;
/// an in-process executor in tests). Returns the executor's response for a
/// length-prefixed signed envelope frame.
pub trait ExecTransport {
    /// Send a framed, signed `ExecRequest` and await the response.
    fn send(
        &self,
        frame: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<ExecResponse, OrchestratorError>>;
}

/// Failures that stop the pipeline (not the same as a *rejection*, which is
/// a normal [`TaskOutcome`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrchestratorError {
    /// The LLM backend failed (transport, status, decode…).
    #[error("llm backend error: {0}")]
    Llm(#[from] LlmError),
    /// Writing the audit log failed. This is fatal: an action that cannot
    /// be audited must not proceed (architecture: no log → no execution).
    #[error("audit error: {0}")]
    Audit(#[from] archangel_audit::AuditError),
    /// Signing the request for boundary B failed.
    #[error("ipc error: {0}")]
    Ipc(#[from] archangel_ipc::IpcError),
    /// The executor transport failed.
    #[error("executor transport error: {0}")]
    Transport(String),
}

/// What happened to one operator task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
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
        /// Reason (also written to the audit log).
        reason: String,
    },
    /// Allowlisted, but the action needs human approval before it can run
    /// (layers #13/#14). Nothing ran — the operator must approve it.
    ApprovalRequired {
        /// Opaque id the operator approves/rejects.
        approval_id: String,
        /// Digest bound to the exact stored action.
        action_digest: String,
        /// The `.exec` bundle awaiting approval.
        exec: String,
        /// Why approval is required (mode/risk).
        reason: String,
        /// Human preview of exactly what will run.
        preview: String,
        /// Whether two independent operator signatures are required.
        two_person: bool,
    },
    /// The session was aborted because the model leaked the canary (#3).
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

/// How long a pending approval stays valid. Short by design: an approval
/// is a deliberate, immediate operator act, not something left lying
/// around. Expired pendings are unusable (fail-closed).
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;

/// Hard cap on simultaneously-pending approvals (anti-DoS).
const MAX_PENDING: usize = 64;

/// An action that passed every gate except the human approval (#13). The
/// **already-signed** boundary-B frame is stored verbatim, so approving
/// runs *exactly* what was proposed — not a re-derived action.
struct Pending {
    /// Signed `ExecRequest` frame, ready to send to the executor as-is.
    frame: Vec<u8>,
    action_id: archangel_core::ActionId,
    exec: String,
    /// Binds exec + args + bundle; the operator must echo this to approve.
    digest: String,
    /// Precomputed for the `ExecRequested` audit record on approval.
    args_sha256: String,
    two_person: bool,
    created_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Unguessable 128-bit approval id (OS CSPRNG), hex-encoded.
fn random_id() -> String {
    use rand::RngCore as _;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let mut s = String::with_capacity(32);
    for x in b {
        s.push(char::from_digit(u32::from(x >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(x & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// Digest binding the approval to the EXACT action: exec name + canonical
/// args + the signed bundle's payload hash. The operator approves this;
/// the daemon refuses if it does not match the stored action.
fn action_digest(
    exec: &str,
    args: &BTreeMap<String, String>,
    payload_sha256: &str,
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(exec.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&serde_json::to_vec(args).unwrap_or_default());
    buf.push(0);
    buf.extend_from_slice(payload_sha256.as_bytes());
    sha256_hex(&buf)
}

/// The orchestrator. One per operator session.
pub struct Orchestrator<B: LlmBackend, T: ExecTransport, S: DurableSink> {
    backend: B,
    transport: T,
    policy: PolicyEngine,
    trust: OperatorTrust,
    bundle_dir: PathBuf,
    audit: AuditLog<S>,
    session: Session,
    secrets: SessionSecrets,
    model: String,
    max_tokens: u32,
    tools: Vec<ToolSpec>,
    pending: HashMap<String, Pending>,
}

impl<B: LlmBackend, T: ExecTransport, S: DurableSink> Orchestrator<B, T, S> {
    /// Assemble an orchestrator. `audit` must already be open (genesis
    /// written) so the chain is anchored before anything is recorded.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        backend: B,
        transport: T,
        policy: PolicyEngine,
        trust: OperatorTrust,
        bundle_dir: PathBuf,
        audit: AuditLog<S>,
        session: Session,
        model: impl Into<String>,
        max_tokens: u32,
        tools: Vec<ToolSpec>,
    ) -> Self {
        Self {
            backend,
            transport,
            policy,
            trust,
            bundle_dir,
            audit,
            session,
            secrets: SessionSecrets::generate(),
            model: model.into(),
            max_tokens,
            tools,
            pending: HashMap::new(),
        }
    }

    /// The per-session signing key the executor must be configured with.
    #[must_use]
    pub fn session_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.session.verifying_key()
    }

    fn builder(&self) -> PromptBuilder {
        PromptBuilder::new(self.secrets.clone(), self.session.mode())
    }

    /// Record the start of the session. Call once before `run_task`.
    pub fn start(&mut self) -> Result<(), OrchestratorError> {
        self.audit.append(AuditEvent::SessionStarted {
            session_id: self.session.id(),
            mode: self.session.mode(),
            profile: self.session.profile().to_owned(),
        })?;
        Ok(())
    }

    /// Run one operator task end to end.
    pub async fn run_task(
        &mut self,
        task: &str,
        untrusted: &[(&str, &str)],
    ) -> Result<TaskOutcome, OrchestratorError> {
        let builder = self.builder();
        let request =
            builder.build(&self.model, self.max_tokens, task, untrusted, &self.tools);

        let mut prompt_digest = request.system.clone().unwrap_or_default();
        for m in &request.messages {
            prompt_digest.push('\n');
            prompt_digest.push_str(&m.content);
        }
        let sid = self.session.id();
        self.audit.append(AuditEvent::LlmRequest {
            session_id: sid,
            backend: self.backend.name().to_owned(),
            model: self.model.clone(),
            prompt_sha256: sha256_hex(prompt_digest.as_bytes()),
        })?;

        let reply: CompletionResponse = self.backend.complete(request).await?;

        let compromised = builder.response_is_compromised(&reply.text);
        self.audit.append(AuditEvent::LlmResponse {
            session_id: sid,
            response_sha256: sha256_hex(reply.text.as_bytes()),
            canary_triggered: compromised,
        })?;
        if compromised {
            self.audit.append(AuditEvent::SessionEnded {
                session_id: sid,
                reason: "canary token leaked: model subverted".to_owned(),
            })?;
            return Ok(TaskOutcome::Compromised);
        }

        match parse_model_response(&reply.text, &builder) {
            Ok(ModelAction::Ask { question }) => Ok(TaskOutcome::Asked { question }),
            Ok(ModelAction::Refuse { reason }) => Ok(TaskOutcome::Refused { reason }),
            Ok(ModelAction::Invoke { exec, args, reason }) => {
                self.invoke(&exec, args, &reason).await
            }
            Err(ResponseError::CanaryLeaked) => {
                // Defense in depth; step above already handles it.
                Ok(TaskOutcome::Compromised)
            }
            Err(e) => {
                let reason = format!("model output violated the bounded contract: {e}");
                self.note(&reason)?;
                Ok(TaskOutcome::Denied {
                    stage: "model-contract".to_owned(),
                    reason,
                })
            }
        }
    }

    async fn invoke(
        &mut self,
        exec: &str,
        args: BTreeMap<String, String>,
        reason: &str,
    ) -> Result<TaskOutcome, OrchestratorError> {
        let sid = self.session.id();
        let action_id = archangel_core::ActionId::new();

        // (#6/#7) verify the signed bundle.
        let exec_path = self.bundle_dir.join(format!("{exec}.exec"));
        let sig_path = self.bundle_dir.join(format!("{exec}.exec.sig"));
        let bundle = match VerifiedBundle::load(&exec_path, &sig_path, &self.trust) {
            Ok(b) => b,
            Err(e) => return self.deny(sid, action_id, exec, "bundle", &e.to_string()),
        };
        if let Err(e) = bundle.validate_args(&args) {
            return self.deny(sid, action_id, exec, "args", &e.to_string());
        }

        // (#8/#9) re-evaluate policy on the bundle's own payload/paths.
        let decision = Self::evaluate_policy(
            &self.policy,
            self.session.profile(),
            self.session.mode(),
            exec,
            &bundle,
        );
        let audit_decision = match &decision {
            PolicyDecision::Allow => Decision::Allow,
            PolicyDecision::RequireApproval { .. } => Decision::RequireApproval,
            PolicyDecision::Deny { .. } | PolicyDecision::NotAllowed { .. } => {
                Decision::Deny
            }
        };
        self.audit.append(AuditEvent::PolicyDecision {
            session_id: sid,
            action_id,
            exec: exec.to_owned(),
            decision: audit_decision,
            reason: format!("{reason} :: {decision:?}"),
        })?;
        // Sign the boundary-B frame now (needed whether we run it
        // immediately or stash it for approval — approving must run
        // *exactly* this signed action, never a re-derived one).
        let envelope = self.session.sign_exec_request(
            action_id,
            exec,
            args.clone(),
            bundle.manifest().meta.risk,
            bundle.manifest().meta.read_only,
        )?;
        let frame = envelope.to_frame()?;
        let digest = action_digest(exec, &args, &bundle.manifest().payload.sha256);
        let args_sha256 = sha256_hex(&serde_json::to_vec(&args).unwrap_or_default());

        match &decision {
            PolicyDecision::Allow => {
                self.dispatch(sid, action_id, exec, &args_sha256, frame).await
            }
            // Layers #13/#14: allowlisted but a human must approve. The
            // signed frame is stashed; nothing runs until `approve`.
            PolicyDecision::RequireApproval { reason, two_person } => {
                self.prune_pending();
                if self.pending.len() >= MAX_PENDING {
                    return Ok(TaskOutcome::Denied {
                        stage: "approval".to_owned(),
                        reason: "too many pending approvals".to_owned(),
                    });
                }
                let approval_id = random_id();
                let preview = format!(
                    "exec={exec} risk={:?} read_only={} args={:?}\npayload: {}",
                    bundle.manifest().meta.risk,
                    bundle.manifest().meta.read_only,
                    args,
                    bundle.manifest().payload.inline
                );
                self.pending.insert(
                    approval_id.clone(),
                    Pending {
                        frame,
                        action_id,
                        exec: exec.to_owned(),
                        digest: digest.clone(),
                        args_sha256,
                        two_person: *two_person,
                        created_ms: now_ms(),
                    },
                );
                Ok(TaskOutcome::ApprovalRequired {
                    approval_id,
                    action_digest: digest,
                    exec: exec.to_owned(),
                    reason: reason.clone(),
                    preview,
                    two_person: *two_person,
                })
            }
            PolicyDecision::Deny { .. } | PolicyDecision::NotAllowed { .. } => {
                Ok(TaskOutcome::Denied {
                    stage: "policy".to_owned(),
                    reason: format!("{decision:?}"),
                })
            }
        }
    }

    /// Audit + send a signed frame to the executor, then record the
    /// outcome. Shared by the immediate-Allow path and `approve`.
    async fn dispatch(
        &mut self,
        sid: archangel_core::SessionId,
        action_id: archangel_core::ActionId,
        exec: &str,
        args_sha256: &str,
        frame: Vec<u8>,
    ) -> Result<TaskOutcome, OrchestratorError> {
        self.audit.append(AuditEvent::ExecRequested {
            session_id: sid,
            action_id,
            exec: exec.to_owned(),
            args_sha256: args_sha256.to_owned(),
        })?;
        let resp = self.transport.send(frame).await?;
        self.record_outcome(sid, action_id, exec, resp)
    }

    /// Drop expired pending approvals (fail-closed: an expired approval is
    /// simply gone).
    fn prune_pending(&mut self) {
        let cutoff = now_ms().saturating_sub(APPROVAL_TTL_MS);
        self.pending.retain(|_, p| p.created_ms >= cutoff);
    }

    /// Approve a pending action: validate it exists, is unexpired, and the
    /// echoed digest matches the exact stored action; then run it. Single-
    /// use. Two-person (#14) is not satisfiable with a single operator
    /// boundary-A key in this build, so such actions are refused
    /// fail-closed (and the pending consumed) — documented limitation
    /// until multi-operator ctl trust lands.
    pub async fn approve(
        &mut self,
        approval_id: &str,
        action_digest: &str,
    ) -> Result<TaskOutcome, OrchestratorError> {
        self.prune_pending();
        let Some(p) = self.pending.remove(approval_id) else {
            return Ok(TaskOutcome::Denied {
                stage: "approval".to_owned(),
                reason: "unknown or expired approval id".to_owned(),
            });
        };
        if p.digest != action_digest {
            return Ok(TaskOutcome::Denied {
                stage: "approval".to_owned(),
                reason: "digest mismatch: approval does not bind the \
                         action that was presented"
                    .to_owned(),
            });
        }
        let sid = self.session.id();
        if p.two_person {
            self.audit.append(AuditEvent::Note {
                message: format!(
                    "two-person rule unsatisfied for {} (single operator \
                     key); refused",
                    p.exec
                ),
            })?;
            return Ok(TaskOutcome::Denied {
                stage: "two-person".to_owned(),
                reason: "critical action needs two independent operator \
                         approvals; multi-operator ctl trust is a later \
                         milestone, so it stays blocked (fail-closed)"
                    .to_owned(),
            });
        }
        self.audit.append(AuditEvent::ApprovalGranted {
            session_id: sid,
            action_id: p.action_id,
            approver: "operator".to_owned(),
        })?;
        self.dispatch(sid, p.action_id, &p.exec, &p.args_sha256, p.frame)
            .await
    }

    /// Reject (discard) a pending action. It never runs.
    pub fn reject(&mut self, approval_id: &str) -> TaskOutcome {
        match self.pending.remove(approval_id) {
            Some(p) => TaskOutcome::Denied {
                stage: "rejected".to_owned(),
                reason: format!("operator rejected {}", p.exec),
            },
            None => TaskOutcome::Denied {
                stage: "approval".to_owned(),
                reason: "unknown or expired approval id".to_owned(),
            },
        }
    }

    fn evaluate_policy(
        policy: &PolicyEngine,
        profile: &str,
        mode: archangel_core::OperationMode,
        exec: &str,
        bundle: &VerifiedBundle,
    ) -> PolicyDecision {
        let m = bundle.manifest();
        let mut intents: Vec<PathIntent<'_>> = m
            .sandbox
            .allowed_paths_ro
            .iter()
            .map(|p| PathIntent {
                path: p,
                access: PathAccess::Read,
            })
            .collect();
        intents.extend(m.sandbox.allowed_paths_rw.iter().map(|p| PathIntent {
            path: p,
            access: PathAccess::Write,
        }));
        let commands = [m.payload.inline.as_str()];
        policy.evaluate(&PolicyRequest {
            profile,
            mode,
            exec,
            risk: m.meta.risk,
            commands: &commands,
            paths: &intents,
        })
    }

    fn record_outcome(
        &mut self,
        sid: archangel_core::SessionId,
        action_id: archangel_core::ActionId,
        exec: &str,
        resp: ExecResponse,
    ) -> Result<TaskOutcome, OrchestratorError> {
        match resp.outcome {
            ExecOutcome::Completed {
                exit_code,
                duration_ms,
                stdout,
                stderr,
                ..
            } => {
                self.audit.append(AuditEvent::ExecCompleted {
                    session_id: sid,
                    action_id,
                    exit_code,
                    duration_ms,
                    stdout_sha256: sha256_hex(stdout.as_bytes()),
                    stderr_sha256: sha256_hex(stderr.as_bytes()),
                })?;
                Ok(TaskOutcome::Executed {
                    exec: exec.to_owned(),
                    exit_code,
                    stdout,
                    stderr,
                })
            }
            ExecOutcome::Rejected { stage, reason } => {
                self.note(&format!("executor rejected ({stage:?}): {reason}"))?;
                Ok(TaskOutcome::Denied {
                    stage: format!("executor:{stage:?}"),
                    reason,
                })
            }
        }
    }

    fn deny(
        &mut self,
        sid: archangel_core::SessionId,
        action_id: archangel_core::ActionId,
        exec: &str,
        stage: &str,
        reason: &str,
    ) -> Result<TaskOutcome, OrchestratorError> {
        self.audit.append(AuditEvent::PolicyDecision {
            session_id: sid,
            action_id,
            exec: exec.to_owned(),
            decision: Decision::Deny,
            reason: format!("{stage}: {reason}"),
        })?;
        Ok(TaskOutcome::Denied {
            stage: stage.to_owned(),
            reason: reason.to_owned(),
        })
    }

    fn note(&mut self, message: &str) -> Result<(), OrchestratorError> {
        self.audit.append(AuditEvent::Note {
            message: message.to_owned(),
        })?;
        Ok(())
    }

    /// Consume the orchestrator, returning its audit log for verification.
    #[must_use]
    pub fn into_audit(self) -> AuditLog<S> {
        self.audit
    }
}

/// Helper for callers that build the audit log: open it over `sink` with a
/// fresh keypair and return both the log and the key (the key verifies the
/// chain later).
pub fn open_audit<S: DurableSink>(
    sink: S,
) -> Result<(AuditLog<S>, AuditKeypair), archangel_audit::AuditError> {
    let keypair = AuditKeypair::generate();
    let secret = keypair.secret_bytes();
    let seed: [u8; 32] = secret
        .expose_secret()
        .try_into()
        .map_err(|_| archangel_audit::AuditError::Crypto("seed".into()))?;
    let log = AuditLog::with_sink(sink, AuditKeypair::from_secret_bytes(&seed))?;
    Ok((log, keypair))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::{
        io::Cursor,
        path::{Path, PathBuf},
        str::FromStr as _,
        sync::{
            atomic::{AtomicU32, Ordering},
            Mutex,
        },
    };

    use async_trait::async_trait;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use archangel_audit::verify_chain;
    use archangel_core::OperationMode;
    use archangel_exec_format::OperatorTrust;
    use archangel_execd::{ActionRunner, ExecLimits, Executor, RunContext, RunResult};
    use archangel_ipc::ExecResponse;
    use archangel_llm::{
        BackendCapability, CompletionRequest, CompletionResponse, LlmBackend, LlmError,
        Usage,
    };
    use archangel_policy::{Allowlist, PolicyEngine};

    use crate::{prompt::ToolSpec, session::Session};

    use super::{open_audit, ExecTransport, Orchestrator, OrchestratorError, TaskOutcome};

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push(char::from_digit(u32::from(x >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(x & 0x0f), 16).unwrap_or('0'));
        }
        s
    }

    fn operator_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn unique_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "archangeld-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn write_bundle(dir: &Path, name: &str, read_only: bool, payload: &str) {
        let sha: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
        let manifest = format!(
            r#"
[meta]
name = "{name}"
version = "1.0.0"
risk = "low"
read_only = {read_only}

[args]
service = {{ type = "string", regex = "[a-z]+", required = true }}

[sandbox]
syscall_profile = "inspect"
network = "none"
timeout_seconds = 5

[payload]
type = "bash"
sha256 = "{}"
inline = "{payload}"
"#,
            hex(&sha)
        );
        let sig = operator_key().sign(manifest.as_bytes()).to_bytes();
        std::fs::write(dir.join(format!("{name}.exec")), &manifest).expect("write exec");
        std::fs::write(dir.join(format!("{name}.exec.sig")), hex(&sig))
            .expect("write sig");
    }

    fn write_bundle_risk(
        dir: &Path,
        name: &str,
        read_only: bool,
        payload: &str,
        risk: &str,
    ) {
        let sha: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
        let manifest = format!(
            "\n[meta]\nname = \"{name}\"\nversion = \"1.0.0\"\nrisk = \"{risk}\"\n\
             read_only = {read_only}\n\n[args]\nservice = {{ type = \"string\", \
             regex = \"[a-z]+\", required = true }}\n\n[sandbox]\n\
             syscall_profile = \"inspect\"\nnetwork = \"none\"\n\
             timeout_seconds = 5\n\n[payload]\ntype = \"bash\"\n\
             sha256 = \"{}\"\ninline = \"{payload}\"\n",
            hex(&sha)
        );
        let sig = operator_key().sign(manifest.as_bytes()).to_bytes();
        std::fs::write(dir.join(format!("{name}.exec")), &manifest).expect("exec");
        std::fs::write(dir.join(format!("{name}.exec.sig")), hex(&sig))
            .expect("sig");
    }

    fn trust() -> OperatorTrust {
        OperatorTrust::from_str(&hex(operator_key().verifying_key().as_bytes()))
            .expect("trust")
    }

    fn policy(allow: &[&str]) -> PolicyEngine {
        let list = allow
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ");
        PolicyEngine::new(
            Allowlist::from_toml(&format!(
                "[[profile]]\nname=\"default\"\nmode=\"read_only\"\nallowed_exec=[{list}]\n"
            ))
            .expect("allowlist"),
        )
    }

    struct MockBackend {
        reply: String,
    }
    #[async_trait]
    impl LlmBackend for MockBackend {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(
            &self,
            _req: CompletionRequest,
        ) -> Result<CompletionResponse, LlmError> {
            Ok(CompletionResponse {
                text: self.reply.clone(),
                model: "mock-1".to_owned(),
                usage: Usage::default(),
            })
        }
        fn supports(&self, _c: BackendCapability) -> bool {
            true
        }
    }

    struct MockRunner;
    impl ActionRunner for MockRunner {
        fn run(&self, _c: &RunContext<'_>) -> RunResult {
            RunResult {
                exit_code: 0,
                duration_ms: 1,
                stdout: "mock-ok".to_owned(),
                stderr: String::new(),
                truncated: false,
            }
        }
    }

    /// In-process transport: drives the REAL executor pipeline so the test
    /// exercises the whole security spine, not a stub.
    struct InProcess {
        executor: Mutex<Executor<MockRunner>>,
    }
    impl ExecTransport for InProcess {
        async fn send(
            &self,
            frame: Vec<u8>,
        ) -> Result<ExecResponse, OrchestratorError> {
            // Strip the 4-byte length prefix exactly like the socket server.
            let body = frame
                .get(4..)
                .ok_or_else(|| OrchestratorError::Transport("short frame".into()))?;
            let mut guard = self
                .executor
                .lock()
                .map_err(|_| OrchestratorError::Transport("executor poisoned".into()))?;
            Ok(guard.handle(body))
        }
    }

    fn orchestrator<'b>(
        reply: &str,
        allow: &[&str],
        dir: PathBuf,
        buf: &'b mut Vec<u8>,
    ) -> Orchestrator<MockBackend, InProcess, &'b mut Vec<u8>> {
        let session = Session::new(OperationMode::ReadOnly, "default");
        let vk = session.verifying_key();
        let executor = Executor::new(
            vk,
            trust(),
            policy(allow),
            dir.clone(),
            ExecLimits::default(),
            MockRunner,
        );
        let (log, _kp) = open_audit(buf).expect("audit");
        Orchestrator::new(
            MockBackend {
                reply: reply.to_owned(),
            },
            InProcess {
                executor: Mutex::new(executor),
            },
            policy(allow),
            trust(),
            dir,
            log,
            session,
            "mock-1",
            256,
            vec![ToolSpec {
                name: "read-logs".to_owned(),
                description: "tail a journal".to_owned(),
                read_only: true,
            }],
        )
    }

    #[tokio::test]
    async fn end_to_end_read_only_executes_and_audits() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi");
        let mut buf = Vec::new();
        {
            let mut orch = orchestrator(
                r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"inspect"}"#,
                &["read-logs"],
                dir.clone(),
                &mut buf,
            );
            orch.start().expect("start");
            let outcome = orch
                .run_task("why is nginx unhappy", &[])
                .await
                .expect("pipeline");
            assert!(
                matches!(
                    &outcome,
                    TaskOutcome::Executed { exec, exit_code: 0, stdout, .. }
                        if exec == "read-logs" && stdout == "mock-ok"
                ),
                "got {outcome:?}"
            );
        }
        // The audit chain must verify against its own genesis-pinned key,
        // which the genesis entry self-declares.
        let text = String::from_utf8(buf.clone()).expect("utf8");
        let first = text.lines().next().expect("genesis line");
        let v: serde_json::Value = serde_json::from_str(first).expect("json");
        let pk_hex = v
            .get("record")
            .and_then(|r| r.get("event"))
            .and_then(|e| e.get("audit_public_key"))
            .and_then(serde_json::Value::as_str)
            .expect("genesis pubkey");
        let vk = archangel_audit::verifying_key_from_hex(pk_hex).expect("vk");
        let head = verify_chain(Cursor::new(&buf), &vk).expect("chain verifies");
        // genesis + SessionStarted + LlmRequest + LlmResponse +
        // PolicyDecision + ExecRequested + ExecCompleted = 7
        assert_eq!(head.entries, 7, "full decision chain recorded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn model_refusal_runs_nothing() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        let mut orch = orchestrator(
            r#"{"action":"refuse","reason":"out of scope"}"#,
            &["read-logs"],
            dir.clone(),
            &mut buf,
        );
        orch.start().expect("start");
        let o = orch.run_task("do something", &[]).await.expect("ok");
        assert!(matches!(o, TaskOutcome::Refused { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn interactive_mode_requires_approval_and_runs_nothing() {
        // Security-critical: in interactive mode the action must NOT run;
        // it is gated on operator approval (#13). This closes the v0.1
        // gap where interactive mode would have executed silently.
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi");
        let mut buf = Vec::new();
        {
            let session = Session::new(OperationMode::Interactive, "ops");
            let vk = session.verifying_key();
            let pol = PolicyEngine::new(
                Allowlist::from_toml(
                    "[[profile]]\nname=\"ops\"\nmode=\"interactive\"\nallowed_exec=[\"read-logs\"]\n",
                )
                .expect("allowlist"),
            );
            let executor = Executor::new(
                vk,
                trust(),
                pol.clone(),
                dir.clone(),
                ExecLimits::default(),
                MockRunner,
            );
            let (log, _kp) = open_audit(&mut buf).expect("audit");
            let mut orch = Orchestrator::new(
                MockBackend {
                    reply: r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"check"}"#
                        .to_owned(),
                },
                InProcess {
                    executor: Mutex::new(executor),
                },
                pol,
                trust(),
                dir.clone(),
                log,
                session,
                "mock-1",
                256,
                vec![ToolSpec {
                    name: "read-logs".to_owned(),
                    description: "tail a journal".to_owned(),
                    read_only: true,
                }],
            );
            orch.start().expect("start");
            let o = orch.run_task("inspect nginx", &[]).await.expect("ok");
            assert!(
                matches!(
                    &o,
                    TaskOutcome::ApprovalRequired { exec, two_person: false, .. }
                        if exec == "read-logs"
                ),
                "interactive mode must gate on approval, got {o:?}"
            );
        }
        // The executor must never have run: no ExecCompleted in the audit.
        let audit = String::from_utf8(buf).expect("utf8");
        assert!(
            !audit.contains("exec_completed"),
            "nothing may execute before approval"
        );
        assert!(audit.contains("require_approval"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build an interactive-mode orchestrator over a bundle of `risk`.
    fn interactive_orch<'b>(
        reply: &str,
        exec: &str,
        risk: &str,
        dir: &std::path::Path,
        buf: &'b mut Vec<u8>,
    ) -> Orchestrator<MockBackend, InProcess, &'b mut Vec<u8>> {
        write_bundle_risk(dir, exec, true, "echo hi", risk);
        let session = Session::new(OperationMode::Interactive, "ops");
        let vk = session.verifying_key();
        let pol = PolicyEngine::new(
            Allowlist::from_toml(&format!(
                "[[profile]]\nname=\"ops\"\nmode=\"interactive\"\nallowed_exec=[\"{exec}\"]\n"
            ))
            .expect("allowlist"),
        );
        let executor = Executor::new(
            vk,
            trust(),
            pol.clone(),
            dir.to_path_buf(),
            ExecLimits::default(),
            MockRunner,
        );
        let (log, _kp) = open_audit(buf).expect("audit");
        Orchestrator::new(
            MockBackend {
                reply: reply.to_owned(),
            },
            InProcess {
                executor: Mutex::new(executor),
            },
            pol,
            trust(),
            dir.to_path_buf(),
            log,
            session,
            "mock-1",
            256,
            vec![ToolSpec {
                name: exec.to_owned(),
                description: "x".to_owned(),
                read_only: true,
            }],
        )
    }

    fn pending_of(o: &TaskOutcome) -> (String, String) {
        match o {
            TaskOutcome::ApprovalRequired {
                approval_id,
                action_digest,
                ..
            } => (approval_id.clone(), action_digest.clone()),
            other => panic!("expected ApprovalRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_runs_exactly_the_proposed_action() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        {
            let mut o = interactive_orch(
                r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"x"}"#,
                "read-logs",
                "medium",
                &dir,
                &mut buf,
            );
            o.start().expect("start");
            let p = o.run_task("inspect", &[]).await.expect("ok");
            let (id, dig) = pending_of(&p);
            let done = o.approve(&id, &dig).await.expect("approve");
            assert!(
                matches!(&done, TaskOutcome::Executed { stdout, .. } if stdout == "mock-ok"),
                "approval must run the stashed signed action, got {done:?}"
            );
            // Single-use: a second approve of the same id is unknown now.
            assert!(matches!(
                o.approve(&id, &dig).await.expect("a2"),
                TaskOutcome::Denied { .. }
            ));
        }
        let audit = String::from_utf8(buf).expect("utf8");
        assert!(audit.contains("approval_granted"));
        assert!(audit.contains("exec_completed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn approve_with_wrong_digest_is_refused_and_runs_nothing() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        {
            let mut o = interactive_orch(
                r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"x"}"#,
                "read-logs",
                "medium",
                &dir,
                &mut buf,
            );
            o.start().expect("start");
            let p = o.run_task("inspect", &[]).await.expect("ok");
            let (id, _dig) = pending_of(&p);
            let r = o.approve(&id, "deadbeef").await.expect("approve");
            assert!(matches!(&r, TaskOutcome::Denied { stage, .. } if stage == "approval"));
        }
        let audit = String::from_utf8(buf).expect("utf8");
        assert!(!audit.contains("exec_completed"), "digest mismatch must not run");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reject_discards_and_then_approve_is_unknown() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        let mut o = interactive_orch(
            r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"x"}"#,
            "read-logs",
            "medium",
            &dir,
            &mut buf,
        );
        o.start().expect("start");
        let p = o.run_task("inspect", &[]).await.expect("ok");
        let (id, dig) = pending_of(&p);
        assert!(matches!(
            o.reject(&id),
            TaskOutcome::Denied { .. }
        ));
        assert!(matches!(
            o.approve(&id, &dig).await.expect("after reject"),
            TaskOutcome::Denied { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_approval_id_is_denied() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        let mut o = interactive_orch("x", "read-logs", "low", &dir, &mut buf);
        o.start().expect("start");
        assert!(matches!(
            o.approve("nope", "nope").await.expect("ok"),
            TaskOutcome::Denied { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn critical_action_two_person_cannot_be_single_approved() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        {
            let mut o = interactive_orch(
                r#"{"action":"danger","args":{"service":"nginx"},"reason":"x"}"#,
                "danger",
                "critical",
                &dir,
                &mut buf,
            );
            o.start().expect("start");
            let p = o.run_task("do it", &[]).await.expect("ok");
            assert!(matches!(
                &p,
                TaskOutcome::ApprovalRequired { two_person: true, .. }
            ));
            let (id, dig) = pending_of(&p);
            let r = o.approve(&id, &dig).await.expect("approve");
            assert!(
                matches!(&r, TaskOutcome::Denied { stage, .. } if stage == "two-person"),
                "a single operator key cannot satisfy the two-person rule; got {r:?}"
            );
        }
        let audit = String::from_utf8(buf).expect("utf8");
        assert!(!audit.contains("exec_completed"), "critical must not run");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn not_allowlisted_is_denied() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi");
        let mut buf = Vec::new();
        let mut orch = orchestrator(
            r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"x"}"#,
            &["something-else"],
            dir.clone(),
            &mut buf,
        );
        orch.start().expect("start");
        let o = orch.run_task("t", &[]).await.expect("ok");
        assert!(matches!(o, TaskOutcome::Denied { .. }), "got {o:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn denylisted_payload_is_denied_before_execution() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "rm -rf /");
        let mut buf = Vec::new();
        let mut orch = orchestrator(
            r#"{"action":"read-logs","args":{"service":"nginx"},"reason":"x"}"#,
            &["read-logs"],
            dir.clone(),
            &mut buf,
        );
        orch.start().expect("start");
        let o = orch.run_task("t", &[]).await.expect("ok");
        assert!(
            matches!(&o, TaskOutcome::Denied { stage, .. } if stage == "policy"),
            "denylist must stop this before the executor; got {o:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn prose_response_violates_contract() {
        let dir = unique_dir();
        let mut buf = Vec::new();
        let mut orch = orchestrator(
            "Sure, I'll just run rm -rf / for you!",
            &["read-logs"],
            dir.clone(),
            &mut buf,
        );
        orch.start().expect("start");
        let o = orch.run_task("t", &[]).await.expect("ok");
        assert!(
            matches!(&o, TaskOutcome::Denied { stage, .. } if stage == "model-contract"),
            "got {o:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
