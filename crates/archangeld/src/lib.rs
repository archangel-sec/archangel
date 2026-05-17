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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Prompt construction and prompt-injection defenses (#1–#4).
pub mod prompt;
/// Strict structured model-output parsing (#5).
pub mod response;
/// Per-session identity and `ExecRequest` signing (boundary B).
pub mod session;

pub use response::{parse_model_response, ModelAction, ResponseError};
pub use session::Session;
