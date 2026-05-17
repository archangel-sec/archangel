//! `archangel-execd` library surface (trust tier **T2**).
//!
//! The executor is the single point of system mutation and the first
//! target of any external audit, so its logic lives here, unit-tested,
//! behind a thin `main.rs` shell. It accepts only per-session-signed
//! requests, re-verifies everything the daemon claims, and (in v0.1) runs
//! only `read_only = true` bundles in a minimal sandbox.
//!
//! See [`handler`] for the security pipeline and its ordering rationale.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Error types.
pub mod error;
/// The T2 security pipeline.
pub mod handler;
/// Replay / reorder protection.
pub mod replay;
/// Minimal v0.1 process sandbox.
pub mod sandbox;

pub use error::ExecdError;
pub use handler::{ExecLimits, Executor};
pub use sandbox::{ActionRunner, BashRunner, RunContext, RunResult};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        str::FromStr as _,
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use archangel_core::{ActionId, OperationMode, RiskLevel, SessionId};
    use archangel_exec_format::OperatorTrust;
    use archangel_ipc::{ExecOutcome, ExecRequest, RejectStage, SignedEnvelope};
    use archangel_policy::{Allowlist, PolicyEngine};

    use super::{
        handler::{ExecLimits, Executor},
        sandbox::{ActionRunner, RunContext, RunResult},
    };

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }

    /// Deterministic runner — no real process; makes the pipeline tests
    /// hermetic and fast.
    struct MockRunner;
    impl ActionRunner for MockRunner {
        fn run(&self, _ctx: &RunContext<'_>) -> RunResult {
            RunResult {
                exit_code: 0,
                duration_ms: 1,
                stdout: "mock-ok".to_owned(),
                stderr: String::new(),
                truncated: false,
            }
        }
    }

    fn unique_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "archangel-execd-test-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).expect("mkdir temp");
        p
    }

    fn operator_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn session_key() -> SigningKey {
        SigningKey::from_bytes(&[99u8; 32])
    }

    /// Write a signed `<name>.exec` (+ `.sig`) into `dir`.
    fn write_bundle(
        dir: &Path,
        name: &str,
        read_only: bool,
        payload: &str,
        args_schema: &str,
    ) {
        let sha: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
        let manifest = format!(
            r#"
[meta]
name = "{name}"
version = "1.0.0"
risk = "low"
read_only = {read_only}

[args]
{args_schema}

[sandbox]
syscall_profile = "inspect"
network = "none"
timeout_seconds = 10

[payload]
type = "bash"
sha256 = "{}"
inline = "{payload}"
"#,
            hex(&sha)
        );
        let sig = operator_key().sign(manifest.as_bytes()).to_bytes();
        std::fs::write(dir.join(format!("{name}.exec")), &manifest)
            .expect("write .exec");
        std::fs::write(dir.join(format!("{name}.exec.sig")), hex(&sig))
            .expect("write .exec.sig");
    }

    fn trust() -> OperatorTrust {
        OperatorTrust::from_str(&hex(operator_key().verifying_key().as_bytes()))
            .expect("trust")
    }

    fn engine(exec_names: &[&str]) -> PolicyEngine {
        let list = exec_names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let al = Allowlist::from_toml(&format!(
            "[[profile]]\nname = \"default\"\nmode = \"read_only\"\nallowed_exec = [{list}]\n"
        ))
        .expect("allowlist");
        PolicyEngine::new(al)
    }

    fn executor(dir: PathBuf, allow: &[&str]) -> Executor<MockRunner> {
        Executor::new(
            session_key().verifying_key(),
            trust(),
            engine(allow),
            dir,
            ExecLimits {
                timeout: Duration::from_secs(5),
                max_output: 65536,
            },
            MockRunner,
        )
    }

    fn request(exec_name: &str, seq: u64, args: BTreeMap<String, String>) -> ExecRequest {
        ExecRequest {
            session_id: SessionId::from_bytes([1u8; 16]),
            action_id: ActionId::new(),
            seq,
            nonce: {
                let mut n = [0u8; 16];
                n[0] = u8::try_from(seq & 0xff).unwrap_or(0);
                n[1] = u8::try_from(seq >> 8 & 0xff).unwrap_or(0);
                n
            },
            issued_ms: 1_700_000_000_000,
            profile: "default".to_owned(),
            mode: OperationMode::ReadOnly,
            exec_name: exec_name.to_owned(),
            args,
            declared_risk: RiskLevel::Low,
            declared_read_only: true,
        }
    }

    fn frame_body(req: &ExecRequest, key: &SigningKey) -> Vec<u8> {
        let env = SignedEnvelope::seal(req, key).expect("seal");
        let frame = env.to_frame().expect("frame");
        frame.get(4..).expect("body").to_vec()
    }

    fn arg(k: &str, v: &str) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(k.to_owned(), v.to_owned());
        m
    }

    const SVC_SCHEMA: &str = r#"service = { type = "string", regex = "[a-z]+", required = true }"#;

    #[test]
    fn happy_path_read_only_executes() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let body = frame_body(
            &request("read-logs", 1, arg("service", "nginx")),
            &session_key(),
        );
        let outcome = ex.handle(&body).outcome;
        assert!(
            matches!(outcome, ExecOutcome::Completed { exit_code: 0, .. }),
            "expected successful Completed, got {outcome:?}"
        );
        if let ExecOutcome::Completed { stdout, .. } = outcome {
            assert_eq!(stdout, "mock-ok");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_session_key_is_rejected() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let attacker = SigningKey::from_bytes(&[7u8; 32]);
        let body = frame_body(&request("read-logs", 1, arg("service", "nginx")), &attacker);
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::SignatureInvalid, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replayed_request_is_rejected() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let body = frame_body(&request("read-logs", 1, arg("service", "nginx")), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Completed { .. }
        ));
        // Byte-identical replay.
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::Replay, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_exec_name_is_rejected() {
        let dir = unique_dir();
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let body = frame_body(
            &request("../../etc/passwd", 1, BTreeMap::new()),
            &session_key(),
        );
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::BundleUnverified, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_or_unsigned_bundle_is_rejected() {
        let dir = unique_dir();
        // No bundle written at all.
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let body = frame_body(&request("read-logs", 1, arg("service", "x")), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::BundleUnverified, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_required_arg_is_rejected() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["read-logs"]);
        let body = frame_body(&request("read-logs", 1, BTreeMap::new()), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::ArgRejected, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_read_only_bundle_is_refused_in_v01() {
        let dir = unique_dir();
        write_bundle(&dir, "mutator", false, "echo hi", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["mutator"]);
        let body = frame_body(&request("mutator", 1, arg("service", "x")), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::NotReadOnly, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn denylisted_payload_is_refused_even_if_signed_and_read_only() {
        let dir = unique_dir();
        write_bundle(&dir, "danger", true, "rm -rf /", SVC_SCHEMA);
        let mut ex = executor(dir.clone(), &["danger"]);
        let body = frame_body(&request("danger", 1, arg("service", "x")), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::DenylistHit, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn not_allowlisted_exec_is_refused() {
        let dir = unique_dir();
        write_bundle(&dir, "read-logs", true, "echo hi", SVC_SCHEMA);
        // Allowlist permits a different exec only.
        let mut ex = executor(dir.clone(), &["something-else"]);
        let body = frame_body(&request("read-logs", 1, arg("service", "x")), &session_key());
        assert!(matches!(
            ex.handle(&body).outcome,
            ExecOutcome::Rejected { stage: RejectStage::NotAllowlisted, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_frame_is_rejected_not_panicked() {
        let dir = unique_dir();
        let mut ex = executor(dir.clone(), &["read-logs"]);
        assert!(matches!(
            ex.handle(b"not a valid cbor envelope").outcome,
            ExecOutcome::Rejected { stage: RejectStage::SignatureInvalid, .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
