//! `archangelctl` — operator CLI. Never privileged itself.
//!
//! v0.1 commands that work today (no daemon required):
//! - `init`       — generate the operator keypair (0600, no-clobber).
//! - `audit-tail` — verify an audit log against a pinned key and show it.
//!
//! `session` / `policy-reload` need the daemon control socket (boundary A,
//! delivered with the `archangeld` runtime milestone); they report that
//! honestly instead of pretending.

#![forbid(unsafe_code)]
// Justification: a CLI's entire purpose is to write results to the
// terminal. Workspace policy permits print in `main` with a justification.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{io::IsTerminal as _, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

use archangelctl::{audit_view, keys, render::Palette};

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
    /// Generate the operator Ed25519 keypair.
    Init {
        /// Path for the secret key (written 0600, never overwritten).
        #[arg(long, default_value = "/etc/archangel/trust/operator.key")]
        secret: PathBuf,
        /// Path for the public key.
        #[arg(long, default_value = "/etc/archangel/trust/operator.pub")]
        public: PathBuf,
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
    /// Start an interactive operator session (needs the daemon).
    Session,
    /// Ask the daemon to reload the signed policy (needs the daemon).
    PolicyReload,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let palette = Palette::detect(cli.no_color, std::io::stdout().is_terminal());

    match cli.command {
        Command::Init { secret, public } => match keys::init_operator_key(&secret, &public) {
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
        },
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
        Command::Session | Command::PolicyReload => {
            eprintln!(
                "archangelctl {}: this command needs the daemon control \
                 socket (boundary A), delivered with the archangeld runtime \
                 milestone. The security spine (prompt defenses, policy, \
                 signed bundles, executor, audit) is implemented and tested; \
                 the operator REPL/ctl protocol is the next milestone.",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::from(64)
        }
    }
}
