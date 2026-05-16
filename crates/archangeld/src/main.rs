//! `archangeld` — the archangel daemon.
//!
//! Trust tier T3 (see `docs/THREAT_MODEL.md`). Talks to the LLM, builds prompts,
//! evaluates policy, and dispatches approved actions to `archangel-execd` over
//! a signed Unix socket. Does not mutate the system itself.

#![forbid(unsafe_code)]

// Justification: this binary is still a stub. Writing a single diagnostic
// line to stderr from `main` before the daemon proper exists is the
// intended behavior; structured tracing is wired in when the runtime is.
// (Workspace policy allows print_stderr in `main` with a justification.)
#[allow(clippy::print_stderr)]
fn main() -> std::process::ExitCode {
    eprintln!(
        "archangeld {} — daemon runtime not yet implemented; library \
         (prompt builder, layers #1-#4) is available. See docs/ARCHITECTURE.md.",
        env!("CARGO_PKG_VERSION")
    );
    std::process::ExitCode::from(64)
}
