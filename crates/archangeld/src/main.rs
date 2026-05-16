//! `archangeld` — the archangel daemon.
//!
//! Trust tier T3 (see `docs/THREAT_MODEL.md`). Talks to the LLM, builds prompts,
//! evaluates policy, and dispatches approved actions to `archangel-execd` over
//! a signed Unix socket. Does not mutate the system itself.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!(
        "archangeld {} — not yet implemented. See docs/ARCHITECTURE.md.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::ExitCode::from(64)
}
