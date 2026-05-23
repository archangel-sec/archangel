//! The `LlmBackend` trait.

use async_trait::async_trait;

use crate::{
    error::LlmError,
    types::{BackendCapability, CompletionRequest, CompletionResponse},
};

/// A pluggable LLM backend.
///
/// `#[async_trait]` is used (rather than native async-fn-in-trait) so the
/// trait stays object-safe: `archangeld` holds a `Box<dyn LlmBackend>` and
/// supports zero-downtime backend switching (e.g. failing over to local
/// Ollama on suspicion of a compromised remote endpoint — see the threat
/// model). `Send + Sync` is required for that shared, multi-task use.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Stable, human-readable backend name (for logs and the audit trail).
    fn name(&self) -> &'static str;

    /// Run one completion. Implementations must enforce the request
    /// timeout, the response-size cap, no redirects, and no proxies.
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Whether the backend advertises a given capability.
    fn supports(&self, capability: BackendCapability) -> bool;
}
