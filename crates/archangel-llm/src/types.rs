//! Backend-neutral request/response types.
//!
//! These types carry a prompt that `archangeld` has *already* hardened
//! (defensive system prompt, spotlighting of untrusted input, canary
//! tokens). Backends in this crate are dumb pipes: they serialize these
//! types to the wire and deserialize the reply. They never interpret,
//! rewrite, or "improve" the prompt — doing so would move security-relevant
//! logic out of the audited prompt builder.

use serde::{Deserialize, Serialize};

/// Who authored a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The operator/daemon side of the conversation.
    User,
    /// The model's prior turns.
    Assistant,
}

/// One conversation turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Author of the message.
    pub role: Role,
    /// Message text. Treated as opaque by this crate.
    pub content: String,
}

impl Message {
    /// A user-authored message.
    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }

    /// An assistant-authored message.
    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
        }
    }
}

/// A completion request. Built by `archangeld`'s prompt builder.
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionRequest {
    /// Model identifier (backend-specific string).
    pub model: String,
    /// System prompt (already hardened by the caller). `None` if unused.
    pub system: Option<String>,
    /// Conversation so far.
    pub messages: Vec<Message>,
    /// Hard cap on tokens the model may generate.
    pub max_tokens: u32,
    /// Optional sampling temperature. `None` = backend default.
    pub temperature: Option<f32>,
}

impl CompletionRequest {
    /// Construct a request with required fields; optional fields default off.
    #[must_use]
    pub fn new(model: impl Into<String>, messages: Vec<Message>, max_tokens: u32) -> Self {
        Self {
            model: model.into(),
            system: None,
            messages,
            max_tokens,
            temperature: None,
        }
    }
}

/// Token accounting reported by the backend (best-effort; some backends
/// only approximate).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens in the prompt.
    pub input_tokens: u32,
    /// Tokens generated.
    pub output_tokens: u32,
}

/// A completion response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionResponse {
    /// The generated text. Still untrusted: the caller must apply canary
    /// and structure checks before acting on it.
    pub text: String,
    /// The model that actually answered (as reported by the backend).
    pub model: String,
    /// Token usage.
    pub usage: Usage,
}

/// Optional capabilities a backend may advertise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendCapability {
    /// Honors a dedicated system prompt field.
    SystemPrompt,
    /// Supports provider-side prompt caching.
    PromptCaching,
    /// Supports constrained/structured output.
    StructuredOutput,
}
