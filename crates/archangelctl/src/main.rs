//! `archangelctl` — operator CLI. Never privileged itself.
//!
//! - `init`          — generate the operator keypair (0600, no-clobber).
//! - `audit-tail`    — verify an audit log against a pinned key and show it.
//! - `session`       — interactive REPL talking to the daemon (boundary A).
//! - `ping`          — liveness check against the daemon.
//! - `policy-reload` — ask the daemon to reload policy.

#![forbid(unsafe_code)]
// Justification: a CLI's entire purpose is to write results to the
// terminal. Workspace policy permits print in `main` with a justification.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{
    io::{IsTerminal as _, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};

use archangel_ctl::CtlRequest;
use archangelctl::{
    audit_view, keys, render::Palette, setup, view, CtlClient, SetupOptions,
};

#[derive(Parser, Debug)]
#[command(name = "archangelctl", version, about = "Operator CLI for archangel")]
struct Cli {
    /// Disable ANSI color even on a TTY.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// One-command bootstrap: keys, trust, sample bundle, allowlist,
    /// config, preflight. Idempotent; never overwrites an existing
    /// operator key, allowlist, or config.
    Setup {
        /// Config root.
        #[arg(long, default_value = "/etc/archangel")]
        etc: PathBuf,
        /// LLM backend: `ollama` (offline) or `anthropic`.
        #[arg(long, default_value = "ollama")]
        backend: String,
        /// Operator UID. Auto-detected from `SUDO_UID` or `/proc` if omitted.
        #[arg(long)]
        operator_uid: Option<u32>,
        /// Daemon UID (auto-detected from the `archangel` user if omitted).
        #[arg(long)]
        daemon_uid: Option<u32>,
        /// Non-default Ollama URL to record.
        #[arg(long)]
        ollama_url: Option<String>,
        /// File containing the Anthropic token (read, written 0600 to
        /// the daemon env file). If omitted and stdin is a TTY, you are
        /// prompted with echo OFF. The token never appears on argv.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Generate the operator Ed25519 keypair.
    Init {
        /// Path for the secret key (written 0600, never overwritten).
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
        /// Path for the public key.
        #[arg(long, default_value = "/etc/archangel/trust/operator.pub")]
        public: PathBuf,
    },
    /// Sign a `.exec` bundle manifest with the operator key.
    BundleSign {
        /// The `.exec` manifest to sign.
        manifest: PathBuf,
        /// Operator secret key.
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
    },
    /// Check whether this host is ready to run archangel.
    Doctor {
        /// Config directory expected to exist.
        #[arg(long, default_value = "/etc/archangel")]
        etc: PathBuf,
        /// Operator key expected to exist.
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        operator_key: PathBuf,
    },
    /// Verify an audit log against a pinned public key and display it.
    AuditTail {
        /// Path to `audit.log.jsonl`.
        #[arg(long, default_value = "/var/log/archangel/audit.log.jsonl")]
        log: PathBuf,
        /// Hex-encoded 32-byte audit public key to pin verification to.
        #[arg(long)]
        key: String,
    },
    /// Interactive operator session (REPL) against the daemon.
    Session {
        /// Operator secret key (signs every control request).
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
        /// Daemon control socket.
        #[arg(long, default_value = "/run/archangel/ctl.sock")]
        socket: PathBuf,
    },
    /// Liveness check against the daemon.
    Ping {
        /// Operator secret key.
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
        /// Daemon control socket.
        #[arg(long, default_value = "/run/archangel/ctl.sock")]
        socket: PathBuf,
    },
    /// Ask the daemon to reload policy.
    PolicyReload {
        /// Operator secret key.
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
        /// Daemon control socket.
        #[arg(long, default_value = "/run/archangel/ctl.sock")]
        socket: PathBuf,
    },
}

fn make_client(secret: &Path, socket: PathBuf) -> Result<CtlClient, ExitCode> {
    match keys::load_operator_key(secret) {
        Ok(k) => Ok(CtlClient::new(socket, k)),
        Err(e) => {
            eprintln!("cannot load operator key {}: {e}", secret.display());
            Err(ExitCode::from(1))
        }
    }
}

async fn one_shot(
    mut client: CtlClient,
    req: CtlRequest,
    palette: Palette,
) -> ExitCode {
    match client.request(req).await {
        Ok(resp) => {
            println!("{}", view::render_response(palette, &resp));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("control request failed: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run_repl(mut client: CtlClient, palette: Palette) -> ExitCode {
    println!(
        "archangel session — free text = a task for the model; \
         /ping, /help, /quit"
    );
    loop {
        print!("› ");
        if std::io::stdout().flush().is_err() {
            return ExitCode::from(1);
        }
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("input error: {e}");
                return ExitCode::from(1);
            }
        }
        let line = line.trim();
        match line {
            "" => {}
            "/quit" | "/exit" => break,
            "/help" => {
                println!("  free text   → run as a task (read-only pipeline)");
                println!("  /ping       → daemon liveness");
                println!("  /quit       → exit");
            }
            "/ping" => {
                respond(&mut client, CtlRequest::Ping, palette).await;
            }
            task => {
                respond(
                    &mut client,
                    CtlRequest::RunTask {
                        task: task.to_owned(),
                        context: Vec::new(),
                    },
                    palette,
                )
                .await;
            }
        }
    }
    ExitCode::SUCCESS
}

async fn respond(client: &mut CtlClient, req: CtlRequest, palette: Palette) {
    match client.request(req).await {
        Ok(resp) => println!("{}", view::render_response(palette, &resp)),
        Err(e) => eprintln!("control request failed: {e}"),
    }
}

/// Read a secret from the controlling TTY with echo OFF (via `stty`, so no
/// extra crate / unsafe). The secret never touches argv or shell history.
fn read_secret_no_echo(prompt: &str) -> std::io::Result<String> {
    use std::io::Write as _;
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let off = std::process::Command::new("stty").arg("-echo").status();
    let mut s = String::new();
    let read = std::io::stdin().read_line(&mut s);
    if off.is_ok_and(|st| st.success()) {
        let _ = std::process::Command::new("stty").arg("echo").status();
    }
    eprintln!();
    read?;
    Ok(s.trim().to_owned())
}

fn write_env_file(path: &std::path::Path, lines: &[String]) -> std::io::Result<()> {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    for l in lines {
        writeln!(f, "{l}")?;
    }
    Ok(())
}

/// Extract a bare token from a file that is either the raw token or a
/// `KEY=value` line. Never logs the value.
fn token_from_file(path: &std::path::Path) -> std::io::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let t = raw.trim();
    Ok(t.split_once('=').map_or(t, |(_, v)| v.trim()).to_owned())
}

#[allow(clippy::too_many_arguments)]
fn do_setup(
    etc: &Path,
    backend: &str,
    operator_uid: Option<u32>,
    daemon_uid: Option<u32>,
    ollama_url: Option<String>,
    token_file: Option<&Path>,
    palette: Palette,
) -> ExitCode {
    let Some(op_uid) = operator_uid.or_else(setup::detect_operator_uid) else {
        eprintln!("could not detect operator UID; pass --operator-uid");
        return ExitCode::from(1);
    };
    let dmn_uid = daemon_uid
        .or_else(setup::detect_daemon_uid)
        .unwrap_or_else(|| {
            eprintln!(
                "note: no 'archangel' system user; using operator UID {op_uid} \
                 as daemon_uid (single-user manual run)"
            );
            op_uid
        });

    let opts = SetupOptions {
        etc: etc.to_path_buf(),
        backend: backend.to_owned(),
        operator_uid: op_uid,
        daemon_uid: dmn_uid,
        ollama_url: ollama_url.clone(),
    };
    match setup::run(&opts, palette) {
        Ok(report) => print!("{report}"),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(1);
        }
    }

    // Secrets/env, written 0600 — never on argv, never echoed.
    let env_path = etc.join("llm.env");
    let mut env_lines: Vec<String> = Vec::new();
    if backend == "anthropic" {
        let token = token_file.map_or_else(
            || {
                if std::io::stdin().is_terminal() {
                    read_secret_no_echo(
                        "Anthropic API token (hidden, blank to skip): ",
                    )
                    .ok()
                    .filter(|t| !t.is_empty())
                } else {
                    None
                }
            },
            |tf| token_from_file(tf).ok().filter(|t| !t.is_empty()),
        );
        match token {
            Some(t) => env_lines.push(format!("ARCHANGEL_LLM_TOKEN={t}")),
            None => eprintln!(
                "no token captured — set ARCHANGEL_LLM_TOKEN before starting \
                 archangeld (or re-run setup with --token-file)"
            ),
        }
    }
    if let Some(url) = ollama_url {
        env_lines.push(format!("ARCHANGEL_OLLAMA_URL={url}"));
    }
    if !env_lines.is_empty() {
        match write_env_file(&env_path, &env_lines) {
            Ok(()) => println!("wrote {} (mode 0600)", env_path.display()),
            Err(e) => eprintln!("could not write {}: {e}", env_path.display()),
        }
    }

    println!(
        "\nNext:\n  manual : run archangeld then archangel-execd with \
         --config {}/archangel.toml, then `archangelctl session`\n  \
         systemd: systemctl enable --now archangel-execd archangeld",
        etc.display()
    );
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let palette = Palette::detect(cli.no_color, std::io::stdout().is_terminal());

    match cli.command {
        Command::Setup {
            etc,
            backend,
            operator_uid,
            daemon_uid,
            ollama_url,
            token_file,
        } => do_setup(
            &etc,
            &backend,
            operator_uid,
            daemon_uid,
            ollama_url,
            token_file.as_deref(),
            palette,
        ),
        Command::Init { secret, public } => {
            match keys::init_operator_key(&secret, &public) {
                Ok(pub_hex) => {
                    println!("operator keypair created");
                    println!("  secret: {} (mode 0600)", secret.display());
                    println!("  public: {} = {pub_hex}", public.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("init failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::BundleSign { manifest, secret } => {
            match keys::sign_bundle(&secret, &manifest) {
                Ok(sig) => {
                    println!("signed: {}", sig.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("bundle-sign failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Doctor { etc, operator_key } => {
            let report = archangelctl::doctor::diagnose(&etc, &operator_key);
            println!("{}", report.render(palette));
            if report.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Command::AuditTail { log, key } => match std::fs::read(&log) {
            Ok(bytes) => {
                print!("{}", audit_view::verify_and_render(&bytes, &key, palette));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("cannot read {}: {e}", log.display());
                ExitCode::from(1)
            }
        },
        Command::Session { secret, socket } => {
            match make_client(&secret, socket) {
                Ok(c) => run_repl(c, palette).await,
                Err(code) => code,
            }
        }
        Command::Ping { secret, socket } => match make_client(&secret, socket) {
            Ok(c) => one_shot(c, CtlRequest::Ping, palette).await,
            Err(code) => code,
        },
        Command::PolicyReload { secret, socket } => {
            match make_client(&secret, socket) {
                Ok(c) => one_shot(c, CtlRequest::ReloadPolicy, palette).await,
                Err(code) => code,
            }
        }
    }
}
