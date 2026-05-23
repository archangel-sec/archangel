//! Local Ollama backend. Compiled in with feature `backend-ollama`.
//!
//! Intended for air-gapped operation: the default endpoint is loopback and
//! no API key is involved. Plaintext `http://` is permitted **only** because
//! the expected peer is local; the hardened client still forbids redirects
//! and environment proxies so a local misconfiguration cannot turn this
//! into an exfiltration channel.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    backend::LlmBackend,
    error::LlmError,
    http,
    types::{BackendCapability, CompletionRequest, CompletionResponse, Role, Usage},
};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
// Seconds is the natural unit for an HTTP timeout and std `Duration` has no
// coarser constructor; the nursery lint's preference does not apply here.
#[allow(clippy::duration_suboptimal_units)]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Configuration for [`OllamaBackend`].
pub struct OllamaConfig {
    /// Base URL. Defaults to loopback `http://127.0.0.1:11434`.
    pub base_url: Option<String>,
    /// Overall per-request timeout (local models can be slow).
    pub timeout: Option<Duration>,
    /// Maximum accepted response size in bytes.
    pub max_response_bytes: Option<usize>,
}

/// The Ollama backend.
pub struct OllamaBackend {
    client: reqwest::Client,
    base_url: String,
    max_response_bytes: usize,
}

impl OllamaBackend {
    /// Build a backend from configuration.
    pub fn new(config: OllamaConfig) -> Result<Self, LlmError> {
        let base_url = config
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned());
        let trimmed = base_url.trim_end_matches('/').to_owned();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err(LlmError::InvalidConfig(format!(
                "Ollama base URL must be http(s)://, got {trimmed:?}"
            )));
        }
        let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT);
        // Local endpoint: TLS not required, but redirects/proxies still off.
        let client = http::build_client(false, timeout)?;
        Ok(Self {
            client,
            base_url: trimmed,
            max_response_bytes: config
                .max_response_bytes
                .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES),
        })
    }
}

const fn role_str(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

#[derive(Serialize)]
struct WireMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct WireOptions {
    num_predict: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    stream: bool,
    options: WireOptions,
}

#[derive(Deserialize)]
struct WireRespMessage {
    #[serde(default)]
    content: String,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    model: String,
    #[serde(default)]
    message: Option<WireRespMessage>,
    #[serde(default)]
    prompt_eval_count: u32,
    #[serde(default)]
    eval_count: u32,
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let mut messages: Vec<WireMessage<'_>> = Vec::new();
        if let Some(system) = request.system.as_deref() {
            messages.push(WireMessage {
                role: "system",
                content: system,
            });
        }
        for m in &request.messages {
            messages.push(WireMessage {
                role: role_str(m.role),
                content: &m.content,
            });
        }

        let body = WireRequest {
            model: &request.model,
            messages,
            stream: false,
            options: WireOptions {
                num_predict: request.max_tokens,
                temperature: request.temperature,
            },
        };

        let url = format!("{}/api/chat", self.base_url);
        let http_req = self.client.post(url).json(&body);

        let bytes = http::send_capped(http_req, self.max_response_bytes).await?;

        let decoded: WireResponse =
            serde_json::from_slice(&bytes).map_err(|e| LlmError::Decode(e.to_string()))?;

        let text = decoded.message.map(|m| m.content).unwrap_or_default();

        Ok(CompletionResponse {
            text,
            model: decoded.model,
            usage: Usage {
                input_tokens: decoded.prompt_eval_count,
                output_tokens: decoded.eval_count,
            },
        })
    }

    fn supports(&self, capability: BackendCapability) -> bool {
        matches!(capability, BackendCapability::SystemPrompt)
    }
}
