//! `archangel-execd` — the archangel executor.
//!
//! Trust tier T2 (see `docs/THREAT_MODEL.md`). The single point of mutation
//! in the system. Accepts only signed requests from `archangeld`, re-validates
//! every request against the denylist and allowlist, verifies `.exec` bundle
//! signatures, and spawns each action inside a per-action sandbox.
//!
//! Keep this crate small. Every line here is in the trusted computing base.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!(
        "archangel-execd {} — not yet implemented. See docs/ARCHITECTURE.md.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::ExitCode::from(64)
}
