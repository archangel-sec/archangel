//! `archangeld` — the archangel daemon (trust tier T3).
//!
//! Wires the tested pieces into a running daemon: load+validate config,
//! open the audit log, build the LLM backend, the policy engine and the
//! signed boundary-B transport, then serve the operator control socket
//! (boundary A) — peer-credential gated, operator-signature verified,
//! replay-protected, one request per connection, processed serially (the
//! sole-mutation executor is serial; serializing bounds blast rate).
//!
//! It never mutates the system itself.

#![forbid(unsafe_code)]
// Justification: startup diagnostics before tracing is initialized, and the
// session-key handoff line the operator needs, go to stderr. Workspace
// policy permits this in `main` with a justification.
#![allow(clippy::print_stderr)]

use std::{
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use clap::Parser;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
};
use tracing::{error, info, warn};

use archangel_audit::{AuditKeypair, AuditLog};
use archangel_core::{OperationMode, SecretString};
use archangel_exec_format::{OperatorTrust, VerifiedBundle};
use archangel_llm::{
    AnthropicBackend, AnthropicConfig, BackendCapability, CompletionRequest,
    CompletionResponse, LlmBackend, LlmError, OllamaBackend, OllamaConfig,
};
use archangel_policy::{Allowlist, PolicyEngine};
use archangeld::{
    prompt::ToolSpec, server::handle_ctl_frame, server::CtlReplayGuard, Config,
    Orchestrator, Session, SocketExecTransport,
};
use archangel_ctl::SignedCtlEnvelope;

#[derive(Parser, Debug)]
#[command(name = "archangeld", version, about = "Archangel daemon (T3)")]
struct Args {
    /// Main configuration file. Everything else comes from it, so the
    /// systemd unit is simply `archangeld --config /etc/archangel/...`.
    #[arg(long, default_value = "/etc/archangel/archangel.toml")]
    config: PathBuf,
}

/// Atomically publish the per-run session public key for the executor to
/// read (write to a temp file `0640`, then rename over the target). It is
/// a *public* key; integrity comes from the directory's permissions, not
/// secrecy. Written before the control socket is bound so the executor
/// never races a missing/!stale file for this run.
fn publish_session_pub(path: &std::path::Path, hex: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(&tmp)
            .context("create session.pub tmp")?;
        f.write_all(hex.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .context("write session.pub")?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).context("rename session.pub into place")?;
    Ok(())
}

/// Runtime backend selector so the daemon can pick one from config without
/// boxing trait objects.
enum AnyBackend {
    Anthropic(AnthropicBackend),
    Ollama(OllamaBackend),
}

#[async_trait]
impl LlmBackend for AnyBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::Anthropic(_) => "anthropic",
            Self::Ollama(_) => "ollama",
        }
    }
    async fn complete(
        &self,
        req: CompletionRequest,
    ) -> Result<CompletionResponse, LlmError> {
        match self {
            Self::Anthropic(b) => b.complete(req).await,
            Self::Ollama(b) => b.complete(req).await,
        }
    }
    fn supports(&self, c: BackendCapability) -> bool {
        match self {
            Self::Anthropic(b) => b.supports(c),
            Self::Ollama(b) => b.supports(c),
        }
    }
}

fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex"));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let hi = nib(*p.first().ok_or_else(|| anyhow!("hex"))?)?;
            let lo = nib(*p.get(1).ok_or_else(|| anyhow!("hex"))?)?;
            Ok((hi << 4) | lo)
        })
        .collect()
}
fn nib(b: u8) -> anyhow::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(anyhow!("bad hex char")),
    }
}
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

fn build_backend(cfg: &Config) -> anyhow::Result<AnyBackend> {
    match cfg.llm.default_backend.as_str() {
        "anthropic" => {
            let token = std::env::var("ARCHANGEL_LLM_TOKEN").context(
                "anthropic backend selected but ARCHANGEL_LLM_TOKEN is not set \
                 (tokens are never read from the config file)",
            )?;
            Ok(AnyBackend::Anthropic(AnthropicBackend::new(
                AnthropicConfig {
                    base_url: None,
                    api_key: SecretString::new(token),
                    timeout: None,
                    max_response_bytes: None,
                },
            )?))
        }
        "ollama" => {
            // ARCHANGEL_OLLAMA_URL lets operators point at a non-default
            // Ollama host (and makes cross-process e2e testing possible).
            // It must be loopback/explicit; the hardened client still
            // forbids redirects and env proxies.
            let base_url = std::env::var("ARCHANGEL_OLLAMA_URL").ok();
            Ok(AnyBackend::Ollama(OllamaBackend::new(OllamaConfig {
                base_url,
                timeout: None,
                max_response_bytes: None,
            })?))
        }
        other => Err(anyhow!("unsupported llm.default_backend {other:?}")),
    }
}

fn load_or_create_audit_key(path: &std::path::Path) -> anyhow::Result<AuditKeypair> {
    if path.exists() {
        let hex = std::fs::read_to_string(path).context("read audit key")?;
        return AuditKeypair::from_secret_hex(hex.trim())
            .map_err(|e| anyhow!("invalid audit key: {e}"));
    }
    let kp = AuditKeypair::generate();
    let seed = kp.secret_bytes();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create audit key")?;
    f.write_all(encode_hex(seed.expose_secret()).as_bytes())
        .context("write audit key")?;
    Ok(kp)
}

/// Rotate an existing audit log aside so each run starts a single-genesis
/// chain (resuming an existing chain is a later milestone).
fn rotate_existing_log(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let mut bak = path.as_os_str().to_owned();
        bak.push(format!(".prev-{ms}"));
        std::fs::rename(path, PathBuf::from(bak)).context("rotate audit log")?;
    }
    Ok(())
}

fn discover_tools(
    bundle_dir: &std::path::Path,
    trust: &OperatorTrust,
    read_only_only: bool,
) -> Vec<ToolSpec> {
    let mut tools = Vec::new();
    let Ok(entries) = std::fs::read_dir(bundle_dir) else {
        return tools;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("exec") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let sig = bundle_dir.join(format!("{stem}.exec.sig"));
        match VerifiedBundle::load(&p, &sig, trust) {
            Ok(b) => {
                let m = b.manifest();
                if read_only_only && !m.meta.read_only {
                    continue;
                }
                tools.push(ToolSpec {
                    name: m.meta.name.clone(),
                    description: format!("v{} risk={:?}", m.meta.version, m.meta.risk),
                    read_only: m.meta.read_only,
                });
            }
            Err(e) => warn!(bundle = %stem, error = %e, "skipping unverifiable bundle"),
        }
    }
    tools
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = Config::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let backend = build_backend(&cfg)?;
    let trust = OperatorTrust::load(&cfg.daemon.trust_store)
        .context("loading operator trust store")?;
    if trust.is_empty() {
        warn!("operator trust store is empty: every .exec bundle will be rejected");
    }
    let allowlist =
        Allowlist::load(&cfg.daemon.allowlist).context("loading allowlist")?;
    let policy = PolicyEngine::new(allowlist);

    let op_pub_hex = std::fs::read_to_string(&cfg.daemon.operator_pubkey)
        .context("read operator pubkey")?;
    let op_bytes: [u8; 32] = decode_hex(&op_pub_hex)?
        .try_into()
        .map_err(|_| anyhow!("operator pubkey must be 32 bytes"))?;
    let operator_pub = ed25519_dalek::VerifyingKey::from_bytes(&op_bytes)
        .context("invalid operator public key")?;

    let audit_kp = load_or_create_audit_key(&cfg.daemon.audit_key)?;
    let audit_pub_hex = audit_kp.public_hex();
    rotate_existing_log(&cfg.daemon.audit_log)?;
    if let Some(parent) = cfg.daemon.audit_log.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let audit = AuditLog::open(&cfg.daemon.audit_log, audit_kp)
        .map_err(|e| anyhow!("opening audit log: {e}"))?;

    let session = Session::new(cfg.modes.default, "default");
    let session_pub_hex = encode_hex(session.verifying_key().as_bytes());

    let read_only = cfg.modes.default == OperationMode::ReadOnly;
    let tools = discover_tools(&cfg.daemon.bundle_dir, &trust, read_only);
    let model = cfg.llm.model.clone().unwrap_or_else(|| {
        match backend.name() {
            "anthropic" => "claude-sonnet-4-6",
            _ => "llama3",
        }
        .to_owned()
    });

    let mut orchestrator = Orchestrator::new(
        backend,
        SocketExecTransport::new(cfg.sockets.exec.clone()),
        policy,
        trust,
        cfg.daemon.bundle_dir.clone(),
        audit,
        session,
        model,
        cfg.llm.max_tokens,
        tools,
    );
    orchestrator.start().map_err(|e| anyhow!("audit start: {e}"))?;

    // Publish the session public key for the executor (architecture §4.2:
    // rotated each daemon restart). The executor reads this file per
    // connection, so it transparently picks up a new key on restart.
    publish_session_pub(&cfg.daemon.session_pub, &session_pub_hex)
        .context("publishing session public key")?;
    eprintln!(
        "session public key published to {} ({session_pub_hex})",
        cfg.daemon.session_pub.display()
    );
    eprintln!("audit log public key (pin this for `archangelctl audit-tail --key`): {audit_pub_hex}");

    if cfg.sockets.control.exists() {
        std::fs::remove_file(&cfg.sockets.control).ok();
    }
    if let Some(parent) = cfg.sockets.control.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener =
        UnixListener::bind(&cfg.sockets.control).context("bind control socket")?;
    std::fs::set_permissions(
        &cfg.sockets.control,
        std::fs::Permissions::from_mode(cfg.sockets.control_mode),
    )
    .context("chmod control socket")?;
    let operator_uid = cfg.sockets.operator_uid;
    info!(
        socket = %cfg.sockets.control.display(),
        operator_uid,
        "control plane listening"
    );

    serve_ctl_loop(listener, operator_uid, operator_pub, orchestrator).await;
    Ok(())
}

/// Serial control-plane accept loop (v0.1). Never returns.
async fn serve_ctl_loop(
    listener: UnixListener,
    operator_uid: u32,
    operator_pub: ed25519_dalek::VerifyingKey,
    mut orchestrator: Orchestrator<AnyBackend, SocketExecTransport, std::fs::File>,
) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(c) if c.uid() == operator_uid => {}
            Ok(c) => {
                warn!(uid = c.uid(), "rejecting unauthorized control peer");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "no peer credentials; rejecting");
                continue;
            }
        }

        if let Err(e) =
            serve_connection(&mut stream, &operator_pub, &mut orchestrator).await
        {
            warn!(error = %e, "control connection ended with error");
        }
    }
}

async fn serve_connection(
    stream: &mut tokio::net::UnixStream,
    operator_pub: &ed25519_dalek::VerifyingKey,
    orchestrator: &mut Orchestrator<AnyBackend, SocketExecTransport, std::fs::File>,
) -> anyhow::Result<()> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await.context("read length")?;
    let len = SignedCtlEnvelope::frame_len(prefix)
        .map_err(|e| anyhow!("frame length rejected: {e}"))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read body")?;

    // One request per connection in v0.1; a fresh replay guard per
    // connection (seq is per-connection).
    let mut guard = CtlReplayGuard::new();
    let response =
        handle_ctl_frame(&body, operator_pub, &mut guard, orchestrator).await;
    stream.write_all(&response).await.context("write response")?;
    stream.flush().await.context("flush")?;
    Ok(())
}
