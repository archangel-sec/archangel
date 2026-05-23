//! `archangel-execd` — the archangel executor (trust tier **T2**).
//!
//! The single point of system mutation. Accepts only per-session-signed
//! requests over a `0600` Unix socket, checks the peer's credentials,
//! re-verifies everything the daemon claims, and (in v0.1) runs only
//! `read_only = true` bundles in a minimal sandbox.
//!
//! Config-driven so the systemd unit is just
//! `archangel-execd --config /etc/archangel/archangel.toml`. The per-run
//! session public key is read from the file `archangeld` publishes
//! (`daemon.session_pub`) **before each connection**, so a daemon restart
//! that rotates the key is picked up without restarting the executor.
//! Individual CLI flags still override config (used by tests).
//!
//! The security pipeline is in the library ([`archangel_execd::Executor`])
//! and is unit-tested there; this binary is the thin socket shell.

#![forbid(unsafe_code)]

use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context as _};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
};
use tracing::{error, info, warn};

use archangel_config::Config;
use archangel_exec_format::OperatorTrust;
use archangel_execd::{BashRunner, ExecLimits, Executor};
use archangel_ipc::{response_to_frame, ExecResponse, RejectStage, SignedEnvelope};
use archangel_policy::{Allowlist, PolicyEngine};

/// Trust tier T2 executor: signed-request only, sandboxed.
#[derive(Parser, Debug)]
#[command(name = "archangel-execd", version)]
struct Args {
    /// Main configuration file (everything below is derived from it; the
    /// systemd unit passes only this).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override: exec socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Override: only accept connections from this peer UID.
    #[arg(long)]
    peer_uid: Option<u32>,
    /// Override: static hex session verifying key (instead of the file).
    #[arg(long)]
    session_pubkey_hex: Option<String>,
    /// Override: path of the published session public key file.
    #[arg(long)]
    session_pub_file: Option<PathBuf>,
    /// Override: operator trust set (`.exec` signing keys).
    #[arg(long)]
    operators: Option<PathBuf>,
    /// Override: allowlist TOML.
    #[arg(long)]
    allowlist: Option<PathBuf>,
    /// Override: signed `.exec` bundle directory.
    #[arg(long)]
    bundle_dir: Option<PathBuf>,
    /// Per-action wall-clock timeout, seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

/// Where the trusted session key comes from.
enum SessionSource {
    /// Fixed for the process lifetime (test / manual use).
    Static(VerifyingKey),
    /// Re-read from this file before every connection (rotation-safe).
    File(PathBuf),
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

fn key_from_hex(hex: &str) -> anyhow::Result<VerifyingKey> {
    let bytes: [u8; 32] = decode_hex(hex)?
        .try_into()
        .map_err(|_| anyhow!("session pubkey must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 session public key")
}

fn read_key_file(path: &std::path::Path) -> anyhow::Result<VerifyingKey> {
    let hex = std::fs::read_to_string(path)
        .with_context(|| format!("reading session key file {}", path.display()))?;
    key_from_hex(hex.trim())
}

/// Resolve a setting: CLI override wins, else config, else a clear error.
fn need<T>(cli: Option<T>, cfg: Option<T>, what: &str) -> anyhow::Result<T> {
    cli.or(cfg).ok_or_else(|| {
        anyhow!("missing required setting: {what} (set it in --config or pass the flag)")
    })
}

fn load_config(arg: Option<&PathBuf>) -> anyhow::Result<Option<Config>> {
    if let Some(p) = arg {
        return Ok(Some(
            Config::load(p).with_context(|| format!("loading {}", p.display()))?,
        ));
    }
    let default = std::path::Path::new("/etc/archangel/archangel.toml");
    if default.exists() {
        Ok(Some(
            Config::load(default).context("loading default config")?,
        ))
    } else {
        Ok(None)
    }
}

/// Fully-resolved runtime settings (CLI overrides applied over config).
struct Settings {
    socket: PathBuf,
    peer_uid: u32,
    operators: PathBuf,
    allowlist: PathBuf,
    bundle_dir: PathBuf,
    session: SessionSource,
    timeout: Duration,
}

fn resolve(args: Args) -> anyhow::Result<Settings> {
    let cfg = load_config(args.config.as_ref())?;
    let socket = need(
        args.socket,
        cfg.as_ref().map(|c| c.sockets.exec.clone()),
        "sockets.exec",
    )?;
    let peer_uid = need(
        args.peer_uid,
        cfg.as_ref().map(|c| c.sockets.daemon_uid),
        "sockets.daemon_uid",
    )?;
    let operators = need(
        args.operators,
        cfg.as_ref().map(|c| c.daemon.trust_store.clone()),
        "daemon.trust_store",
    )?;
    let allowlist = need(
        args.allowlist,
        cfg.as_ref().map(|c| c.daemon.allowlist.clone()),
        "daemon.allowlist",
    )?;
    let bundle_dir = need(
        args.bundle_dir,
        cfg.as_ref().map(|c| c.daemon.bundle_dir.clone()),
        "daemon.bundle_dir",
    )?;
    let session = if let Some(hex) = &args.session_pubkey_hex {
        SessionSource::Static(key_from_hex(hex).context("--session-pubkey-hex")?)
    } else {
        SessionSource::File(need(
            args.session_pub_file,
            cfg.as_ref().map(|c| c.daemon.session_pub.clone()),
            "daemon.session_pub",
        )?)
    };
    Ok(Settings {
        socket,
        peer_uid,
        operators,
        allowlist,
        bundle_dir,
        session,
        timeout: Duration::from_secs(args.timeout_secs),
    })
}

/// Serial accept loop (v0.1): one action at a time bounds blast rate and
/// avoids session-key refresh races. Never returns.
async fn serve_loop(
    listener: UnixListener,
    peer_uid: u32,
    session: SessionSource,
    mut executor: Executor<BashRunner>,
) {
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
            Ok(cred) if cred.uid() == peer_uid => {}
            Ok(cred) => {
                warn!(uid = cred.uid(), "rejecting unauthorized peer");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "no peer credentials; rejecting");
                continue;
            }
        }

        // Refresh the trusted session key from the published file so a
        // daemon restart (rotation) is picked up. Fail-closed: a missing
        // or invalid file drops the connection rather than trust a stale
        // key.
        if let SessionSource::File(p) = &session {
            match read_key_file(p) {
                Ok(k) => executor.set_session_key(k),
                Err(e) => {
                    warn!(error = %e, "session key unavailable; dropping connection");
                    continue;
                }
            }
        }

        if let Err(e) = serve_one(&mut stream, &mut executor).await {
            warn!(error = %e, "connection ended with error");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let s = resolve(Args::parse())?;

    let trust = OperatorTrust::load(&s.operators).context("operator trust set")?;
    if trust.is_empty() {
        warn!("operator trust set is empty: every bundle will be rejected");
    }
    let policy = PolicyEngine::new(Allowlist::load(&s.allowlist).context("allowlist")?);

    // For File mode the real key is reloaded before every connection (and
    // a missing file drops the connection), so this placeholder is never
    // used to verify anything; a deterministic throwaway keeps it
    // infallible.
    let initial_key = match &s.session {
        SessionSource::Static(k) => *k,
        SessionSource::File(p) => read_key_file(p).unwrap_or_else(|e| {
            warn!(error = %e, "session key not published yet; rejecting until it is");
            ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]).verifying_key()
        }),
    };

    // #16: a BTRFS snapshot backend if the state dir is on BTRFS, else
    // None (⇒ any mutating action is refused fail-closed by the executor).
    let snap_root = std::path::Path::new("/var/lib/archangel-exec/snapshots");
    let snapshotter = archangel_snapshot::detect_for(
        std::path::Path::new("/var/lib/archangel-exec"),
        snap_root.to_path_buf(),
    );
    if let Some(s) = &snapshotter {
        info!(backend = s.backend(), "snapshot backend ready");
    } else {
        warn!(
            "no snapshot backend (state dir not BTRFS): mutating actions \
             will be refused fail-closed (read-only is unaffected)"
        );
    }

    let executor = Executor::new(
        initial_key,
        trust,
        policy,
        s.bundle_dir.clone(),
        ExecLimits {
            timeout: s.timeout,
            max_output: 1024 * 1024,
        },
        BashRunner,
        snapshotter,
    );

    if s.socket.exists() {
        std::fs::remove_file(&s.socket).context("removing stale socket")?;
    }
    if let Some(parent) = s.socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(&s.socket).context("bind exec socket")?;
    std::fs::set_permissions(&s.socket, std::fs::Permissions::from_mode(0o600))
        .context("chmod exec socket")?;
    info!(socket = %s.socket.display(), peer_uid = s.peer_uid, "executor listening");

    serve_loop(listener, s.peer_uid, s.session, executor).await;
    Ok(())
}

async fn serve_one(
    stream: &mut tokio::net::UnixStream,
    executor: &mut Executor<BashRunner>,
) -> anyhow::Result<()> {
    let mut prefix = [0u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .context("read length")?;
    let len =
        SignedEnvelope::frame_len(prefix).map_err(|e| anyhow!("frame length rejected: {e}"))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read body")?;

    let response: ExecResponse = executor.handle(&body);

    let frame = response_to_frame(&response).unwrap_or_else(|_| {
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
