//! Cross-process end-to-end test of the **real** `archangel-execd` binary.
//!
//! This is not an in-process harness: it spawns the actual compiled
//! executor, connects to its real Unix socket, and exercises the entire
//! trust-boundary-B path as a separate process —
//!
//! - real peer-credential gate (same uid passes),
//! - real per-session Ed25519 signature verification,
//! - real signed `.exec` bundle verification (operator sig + payload hash),
//! - real denylist + allowlist re-evaluation,
//! - real read-only enforcement,
//! - real minimal sandbox running an actual command.
//!
//! It plays the role `archangeld` plays at runtime: produce a signed
//! request. No LLM is involved (the daemon's job of signing requests is
//! exactly what we simulate here).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use archangel_core::{ActionId, OperationMode, RiskLevel, SessionId};
use archangel_ipc::{response_from_frame_body, ExecOutcome, ExecRequest, SignedEnvelope};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from_digit(u32::from(x >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(x & 0x0f), 16).unwrap());
    }
    s
}

fn current_uid() -> u32 {
    let out = Command::new("id").arg("-u").output().expect("run id -u");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("uid parse")
}

/// Kills the spawned executor when the test ends, pass or fail.
struct Reaper(Child);
impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_signed_bundle(dir: &Path, name: &str, operator: &SigningKey) {
    let payload = "echo archangel-e2e-ok";
    let sha: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    let manifest = format!(
        r#"
[meta]
name = "{name}"
version = "1.0.0"
risk = "low"
read_only = true

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
    let sig = operator.sign(manifest.as_bytes()).to_bytes();
    std::fs::write(dir.join(format!("{name}.exec")), &manifest).unwrap();
    std::fs::write(dir.join(format!("{name}.exec.sig")), hex(&sig)).unwrap();
}

#[tokio::test]
async fn real_execd_runs_a_signed_read_only_bundle() {
    let tmp = std::env::temp_dir().join(format!(
        "archangel-xproc-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let bundle_dir = tmp.join("exec");
    std::fs::create_dir_all(&bundle_dir).unwrap();

    // Operator key signs the .exec bundle; session key signs the request.
    let operator = SigningKey::from_bytes(&[11u8; 32]);
    let session = SigningKey::from_bytes(&[22u8; 32]);

    write_signed_bundle(&bundle_dir, "read-logs", &operator);
    let operators_file = tmp.join("operators.pubkeys");
    std::fs::write(
        &operators_file,
        format!(
            "{}  e2e-operator\n",
            hex(operator.verifying_key().as_bytes())
        ),
    )
    .unwrap();
    let allowlist = tmp.join("allowlist.toml");
    std::fs::write(
        &allowlist,
        "[[profile]]\nname=\"default\"\nmode=\"read_only\"\nallowed_exec=[\"read-logs\"]\n",
    )
    .unwrap();

    let sock = tmp.join("exec.sock");
    let exe = env!("CARGO_BIN_EXE_archangel-execd");

    let child = Command::new(exe)
        .arg("--socket")
        .arg(&sock)
        .arg("--peer-uid")
        .arg(current_uid().to_string())
        .arg("--session-pubkey-hex")
        .arg(hex(session.verifying_key().as_bytes()))
        .arg("--operators")
        .arg(&operators_file)
        .arg("--allowlist")
        .arg(&allowlist)
        .arg("--bundle-dir")
        .arg(&bundle_dir)
        .arg("--timeout-secs")
        .arg("10")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn archangel-execd");
    let _reaper = Reaper(child);

    // Wait for the executor to bind its socket.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(
            Instant::now() < deadline,
            "executor never created its socket"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Small grace so the listener is actually accepting.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = ExecRequest {
        session_id: SessionId::new(),
        action_id: ActionId::new(),
        seq: 1,
        nonce: [1u8; 16],
        issued_ms: 1,
        profile: "default".to_owned(),
        mode: OperationMode::ReadOnly,
        exec_name: "read-logs".to_owned(),
        args: std::collections::BTreeMap::new(),
        declared_risk: RiskLevel::Low,
        declared_read_only: true,
    };
    let frame = SignedEnvelope::seal(&request, &session)
        .expect("seal")
        .to_frame()
        .expect("frame");

    let mut stream = tokio::net::UnixStream::connect(&sock)
        .await
        .expect("connect exec socket");
    stream.write_all(&frame).await.expect("write request");
    stream.flush().await.expect("flush");

    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await.expect("read prefix");
    let len = u32::from_be_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.expect("read body");
    let resp = response_from_frame_body(&body).expect("decode response");

    match resp.outcome {
        ExecOutcome::Completed {
            exit_code, stdout, ..
        } => {
            assert_eq!(exit_code, 0, "read-only command should succeed");
            assert!(
                stdout.contains("archangel-e2e-ok"),
                "real sandbox must have run the real payload, got: {stdout:?}"
            );
        }
        other @ ExecOutcome::Rejected { .. } => {
            panic!("expected Completed from the real executor, got {other:?}")
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn real_execd_rejects_a_foreign_session_signature() {
    let tmp = std::env::temp_dir().join(format!(
        "archangel-xproc-bad-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let bundle_dir = tmp.join("exec");
    std::fs::create_dir_all(&bundle_dir).unwrap();

    let operator = SigningKey::from_bytes(&[11u8; 32]);
    let real_session = SigningKey::from_bytes(&[22u8; 32]);
    let attacker = SigningKey::from_bytes(&[99u8; 32]);

    write_signed_bundle(&bundle_dir, "read-logs", &operator);
    let operators_file = tmp.join("operators.pubkeys");
    std::fs::write(
        &operators_file,
        format!("{}\n", hex(operator.verifying_key().as_bytes())),
    )
    .unwrap();
    let allowlist = tmp.join("allowlist.toml");
    std::fs::write(
        &allowlist,
        "[[profile]]\nname=\"default\"\nmode=\"read_only\"\nallowed_exec=[\"read-logs\"]\n",
    )
    .unwrap();

    let sock = tmp.join("exec.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_archangel-execd"))
        .args([
            "--socket".as_ref(),
            sock.as_os_str(),
            "--peer-uid".as_ref(),
            current_uid().to_string().as_ref(),
            "--session-pubkey-hex".as_ref(),
            // Executor trusts the REAL session key...
            hex(real_session.verifying_key().as_bytes()).as_ref(),
            "--operators".as_ref(),
            operators_file.as_os_str(),
            "--allowlist".as_ref(),
            allowlist.as_os_str(),
            "--bundle-dir".as_ref(),
            bundle_dir.as_os_str(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let _reaper = Reaper(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "no socket");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = ExecRequest {
        session_id: SessionId::new(),
        action_id: ActionId::new(),
        seq: 1,
        nonce: [2u8; 16],
        issued_ms: 1,
        profile: "default".to_owned(),
        mode: OperationMode::ReadOnly,
        exec_name: "read-logs".to_owned(),
        args: std::collections::BTreeMap::new(),
        declared_risk: RiskLevel::Low,
        declared_read_only: true,
    };
    // ...but the attacker signs it with the wrong key.
    let frame = SignedEnvelope::seal(&request, &attacker)
        .expect("seal")
        .to_frame()
        .expect("frame");

    let mut stream = tokio::net::UnixStream::connect(&sock)
        .await
        .expect("connect");
    stream.write_all(&frame).await.expect("write");
    stream.flush().await.expect("flush");
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await.expect("prefix");
    let len = u32::from_be_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.expect("body");
    let resp = response_from_frame_body(&body).expect("decode");

    assert!(
        matches!(resp.outcome, ExecOutcome::Rejected { .. }),
        "the real executor must reject a foreign-signed request, got {:?}",
        resp.outcome
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
