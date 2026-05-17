//! `archangel-execd` — the archangel executor (trust tier **T2**).
//!
//! The single point of system mutation. Accepts only per-session-signed
//! requests over a `0600` Unix socket, checks the peer's credentials,
//! re-verifies everything the daemon claims, and (in v0.1) runs only
//! `read_only = true` bundles in a minimal sandbox.
//!
//! The security pipeline is in the library ([`archangel_execd::Executor`])
//! and is unit-tested there; this binary is the thin socket shell.

#![forbid(unsafe_code)]

use std::{
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use clap::Parser;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
    sync::Mutex,
};
use tracing::{error, info, warn};

use archangel_exec_format::OperatorTrust;
use archangel_ipc::{response_to_frame, ExecResponse, RejectStage, SignedEnvelope};
use archangel_policy::{Allowlist, PolicyEngine};
use archangel_execd::{BashRunner, ExecLimits, Executor};

/// Trust tier T2 executor: signed-request only, sandboxed.
#[derive(Parser, Debug)]
#[command(name = "archangel-execd", version)]
struct Args {
    /// Unix socket path to listen on.
    #[arg(long, default_value = "/run/archangel/exec.sock")]
    socket: PathBuf,

    /// Only accept connections from this peer UID (the archangel daemon
    /// user). Required: there is no insecure "accept any peer" default.
    #[arg(long)]
    peer_uid: u32,

    /// Hex-encoded 32-byte Ed25519 session verifying key (rotated each
    /// daemon restart).
    #[arg(long)]
    session_pubkey_hex: String,

    /// Path to `operators.pubkeys` (the `.exec` signing trust set).
    #[arg(long)]
    operators: PathBuf,

    /// Path to the allowlist TOML.
    #[arg(long)]
    allowlist: PathBuf,

    /// Directory holding signed `.exec` bundles.
    #[arg(long)]
    bundle_dir: PathBuf,

    /// Per-action wall-clock timeout, seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex"));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let hi = nibble(*p.first().ok_or_else(|| anyhow!("hex"))?)?;
            let lo = nibble(*p.get(1).ok_or_else(|| anyhow!("hex"))?)?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn nibble(b: u8) -> anyhow::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(anyhow!("invalid hex char")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let key_bytes: [u8; 32] = decode_hex(&args.session_pubkey_hex)
        .context("session pubkey hex")?
        .try_into()
        .map_err(|_| anyhow!("session pubkey must be 32 bytes"))?;
    let session_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .context("invalid Ed25519 session public key")?;

    let trust = OperatorTrust::load(&args.operators).context("operator trust set")?;
    if trust.is_empty() {
        warn!("operator trust set is empty: every bundle will be rejected");
    }
    let allowlist = Allowlist::load(&args.allowlist).context("allowlist")?;
    let policy = PolicyEngine::new(allowlist);

    let executor = Arc::new(Mutex::new(Executor::new(
        session_key,
        trust,
        policy,
        args.bundle_dir.clone(),
        ExecLimits {
            timeout: Duration::from_secs(args.timeout_secs),
            max_output: 1024 * 1024,
        },
        BashRunner,
    )));

    // Fresh socket, locked down before anyone can connect.
    if args.socket.exists() {
        std::fs::remove_file(&args.socket).context("removing stale socket")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind exec socket")?;
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))
        .context("chmod exec socket")?;
    info!(socket = %args.socket.display(), peer_uid = args.peer_uid, "executor listening");

    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };

        // Peer-credential gate (architecture §4.2 SCM_CREDENTIALS).
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == args.peer_uid => {}
            Ok(cred) => {
                warn!(uid = cred.uid(), "rejecting connection from unauthorized peer");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "could not read peer credentials; rejecting");
                continue;
            }
        }

        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            if let Err(e) = serve_one(&mut stream, &executor).await {
                warn!(error = %e, "connection ended with error");
            }
        });
    }
}

async fn serve_one(
    stream: &mut tokio::net::UnixStream,
    executor: &Arc<Mutex<Executor<BashRunner>>>,
) -> anyhow::Result<()> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await.context("read length")?;
    let len = SignedEnvelope::frame_len(prefix)
        .map_err(|e| anyhow!("frame length rejected: {e}"))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read body")?;

    // Serial processing (v0.1): the sole mutation point handles one action
    // at a time, bounding blast rate.
    let response: ExecResponse = {
        let mut guard = executor.lock().await;
        guard.handle(&body)
    };

    let frame = response_to_frame(&response)
        .unwrap_or_else(|_| {
            // Should never happen; if it does, send a minimal rejection.
            let fallback = ExecResponse::rejected(
                archangel_core::ActionId::from_bytes([0u8; 16]),
                RejectStage::ExecFailure,
                "response encoding failed",
            );
            response_to_frame(&fallback).unwrap_or_default()
        });
    stream.write_all(&frame).await.context("write response")?;
    stream.flush().await.context("flush")?;
    Ok(())
}
