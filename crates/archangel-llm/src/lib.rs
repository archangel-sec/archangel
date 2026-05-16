//! LLM backend abstraction.
//!
//! Defines the `LlmBackend` trait and ships adapters behind feature flags:
//! `backend-anthropic`, `backend-ollama`, `backend-openai-compat`.
//!
//! All requests are built by the prompt builder in `archangeld`, which applies
//! layers #1, #2, and #3 (defensive system prompt, spotlighting, canary tokens).
//! Backends here are dumb pipes — they do not interpret or modify the prompt.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
