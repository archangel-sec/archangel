//! `archangeld` library surface.
//!
//! The binary (`src/main.rs`) is a thin shell; the testable logic lives
//! here. Trust tier T3 (see `docs/THREAT_MODEL.md`): this process talks to
//! the LLM and evaluates policy, but **never mutates the system** — that is
//! `archangel-execd`'s sole responsibility.
//!
//! Implemented so far: the prompt builder ([`prompt`]) — defense layers
//! #1–#4 against prompt injection, the project's stated #1 risk.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Prompt construction and prompt-injection defenses (#1–#4).
pub mod prompt;
