//! `archangeld` library surface.
//!
//! The binary (`src/main.rs`) is a thin shell; the testable logic lives
//! here. Trust tier T3 (see `docs/THREAT_MODEL.md`): this process talks to
//! the LLM and evaluates policy, but **never mutates the system** — that is
//! `archangel-execd`'s sole responsibility.
//!
//! Implemented so far:
//! - [`prompt`] — defense layers #1–#4 against prompt injection.
//! - [`response`] — layer #5: strict, bounded parsing of model output.
//! - [`session`] — per-session signing for trust boundary B.
//! - [`orchestrator`] — the read-only end-to-end pipeline tying every
//!   layer together and recording the decision chain to the audit log.
//! - [`monitor`] — bounded, rotation-aware log tailing (sensory foundation
//!   for autonomous mode; logs are treated as hostile, T6).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Real-time log monitoring (sensory foundation; logs are hostile, T6).
pub mod monitor;
/// The read-only orchestration pipeline.
pub mod orchestrator;
/// Prompt construction and prompt-injection defenses (#1–#4).
pub mod prompt;
/// Strict structured model-output parsing (#5).
pub mod response;
/// Control-plane socket server (boundary-A enforcement).
pub mod server;
/// Per-session identity and `ExecRequest` signing (boundary B).
pub mod session;
/// Production executor transport (boundary-B client over a Unix socket).
pub mod transport;

pub use archangel_config::{Config, ConfigError};
pub use monitor::{
    Alert, CooldownGate, LogEvent, LogMatcher, LogMonitor, LogTailer, MonitorError, MonitorLimits,
    Pattern,
};
pub use orchestrator::{ExecTransport, Orchestrator, OrchestratorError, TaskOutcome};
pub use response::{parse_model_response, ModelAction, ResponseError};
pub use server::{handle_ctl_frame, CtlReplayGuard, CtlService};
pub use session::Session;
pub use transport::SocketExecTransport;
