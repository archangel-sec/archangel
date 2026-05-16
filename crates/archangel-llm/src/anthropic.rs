//! Anthropic (Claude) backend. Compiled in with feature `backend-anthropic`.
//!
//! A dumb pipe to the Messages API: it serializes the already-hardened
//! prompt, sends it over the hardened client, and decodes the reply. It
//! does not add instructions, retry with mutated prompts, or interpret the
//! response.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use archangel_core::SecretString;

use crate::{
    backend::LlmBackend,
    error::LlmError,
    http,
    types::{BackendCapability, CompletionRequest, CompletionResponse, Role, Usage},
};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
// Seconds is the natural unit for an HTTP timeout and std `Duration` has no
// coarser constructor; the nursery lint's preference does not apply here.
#[allow(clippy::duration_suboptimal_units)]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Configuration for [`AnthropicBackend`].
pub struct AnthropicConfig {
    /// API base URL. Must be `https://`. Defaults to the public endpoint.
    pub base_url: Option<String>,
    /// API key. Held as a [`SecretString`]; never logged.
    pub api_key: SecretString,
    /// Overall per-request timeout.
    pub timeout: Option<Duration>,
    /// Maximum accepted response size in bytes.
    pub max_response_bytes: Option<usize>,
}

/// The Anthropic backend.
pub struct AnthropicBackend {
    client: reqwest::Client,
    base_url: String,
    api_key: SecretString,
    max_response_bytes: usize,
}

impl AnthropicBackend {
    /// Build a backend from configuration.
    ///
    /// Rejects a non-`https` base URL before any network use: sending the
    /// API key to a plaintext endpoint is never allowed.
    pub fn new(config: AnthropicConfig) -> Result<Self, LlmError> {
        let base_url = config
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned());
        let trimmed = base_url.trim_end_matches('/').to_owned();
        if !trimmed.starts_with("https://") {
            return Err(LlmError::InvalidConfig(format!(
                "Anthropic base URL must be https://, got {trimmed:?}"
            )));
        }
        let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT);
        let client = http::build_client(true, timeout)?;
        Ok(Self {
            client,
            base_url: trimmed,
            api_key: config.api_key,
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
struct WireRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Deserialize)]
struct WireBlock {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    content: Vec<WireBlock>,
    #[serde(default)]
    model: String,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, LlmError> {
        let messages: Vec<WireMessage<'_>> = request
            .messages
            .iter()
            .map(|m| WireMessage {
                role: role_str(m.role),
                content: &m.content,
            })
            .collect();

        let body = WireRequest {
            model: &request.model,
            max_tokens: request.max_tokens,
            system: request.system.as_deref(),
            messages,
            temperature: request.temperature,
        };

        let url = format!("{}/v1/messages", self.base_url);
        let http_req = self
            .client
            .post(url)
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body);

        let bytes = http::send_capped(http_req, self.max_response_bytes).await?;

        let decoded: WireResponse = serde_json::from_slice(&bytes)
            .map_err(|e| LlmError::Decode(e.to_string()))?;

        let text: String = decoded
            .content
            .iter()
            .filter(|b| b.ty == "text")
            .map(|b| b.text.as_str())
            .collect();

        let usage = decoded.usage.map_or_else(Usage::default, |u| Usage {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
        });

        Ok(CompletionResponse {
            text,
            model: decoded.model,
            usage,
        })
    }

    fn supports(&self, capability: BackendCapability) -> bool {
        matches!(
            capability,
            BackendCapability::SystemPrompt
                | BackendCapability::PromptCaching
                | BackendCapability::StructuredOutput
        )
    }
}
