//! `archangelctl` — operator CLI.
//!
//! Talks to the daemon over `/run/archangel/ctl.sock`. Never privileged itself.
//! Holds the operator's signing key (or a reference to a hardware-backed key)
//! and signs control-plane requests.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!(
        "archangelctl {} — not yet implemented. See docs/ARCHITECTURE.md.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::ExitCode::from(64)
}
