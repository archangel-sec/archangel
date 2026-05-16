//! LLM backend abstraction.
//!
//! Defines the [`LlmBackend`] trait and ships adapters behind feature flags:
//! `backend-anthropic`, `backend-ollama`, `backend-openai-compat`.
//!
//! All requests are built by the prompt builder in `archangeld`, which
//! applies layers #1–#3 (defensive system prompt, spotlighting, canary
//! tokens). **Backends here are dumb pipes — they never interpret, rewrite,
//! or "improve" the prompt.** Centralizing prompt security in one audited
//! place is the whole point; a backend that "helpfully" edited the prompt
//! would be a security regression.
//!
//! The transport is hardened (see [`http`]): no redirects, no environment
//! proxy, mandatory timeouts, rustls-only, TLS required for remote
//! endpoints, and a hard response-size cap.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Error types.
pub mod error;
/// Backend-neutral request/response types.
pub mod types;
/// The `LlmBackend` trait.
pub mod backend;

#[cfg(any(feature = "backend-anthropic", feature = "backend-ollama"))]
mod http;

#[cfg(feature = "backend-anthropic")]
/// Anthropic (Claude) backend.
pub mod anthropic;
#[cfg(feature = "backend-ollama")]
/// Local Ollama backend.
pub mod ollama;

pub use backend::LlmBackend;
pub use error::LlmError;
pub use types::{
    BackendCapability, CompletionRequest, CompletionResponse, Message, Role, Usage,
};

#[cfg(feature = "backend-anthropic")]
pub use anthropic::{AnthropicBackend, AnthropicConfig};
#[cfg(feature = "backend-ollama")]
pub use ollama::{OllamaBackend, OllamaConfig};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::types::{BackendCapability, Message, Role};

    #[test]
    fn role_serializes_lowercase() {
        let json = serde_json::to_string(&Role::Assistant).expect("serialize");
        assert_eq!(json, "\"assistant\"");
    }

    #[test]
    fn message_helpers_set_roles() {
        assert_eq!(Message::user("hi").role, Role::User);
        assert_eq!(Message::assistant("yo").role, Role::Assistant);
    }

    #[cfg(feature = "backend-anthropic")]
    mod anthropic {
        use archangel_core::SecretString;

        use crate::{
            anthropic::{AnthropicBackend, AnthropicConfig},
            backend::LlmBackend,
            error::LlmError,
            types::BackendCapability,
        };

        #[test]
        fn rejects_plaintext_endpoint() {
            // Sending the API key over http:// must be refused up front.
            let cfg = AnthropicConfig {
                base_url: Some("http://api.anthropic.com".to_owned()),
                api_key: SecretString::from("sk-test"),
                timeout: None,
                max_response_bytes: None,
            };
            assert!(matches!(
                AnthropicBackend::new(cfg),
                Err(LlmError::InvalidConfig(_))
            ));
        }

        #[test]
        fn accepts_https_and_reports_capabilities() {
            let cfg = AnthropicConfig {
                base_url: None,
                api_key: SecretString::from("sk-test"),
                timeout: None,
                max_response_bytes: None,
            };
            let backend = AnthropicBackend::new(cfg).expect("https config is valid");
            assert_eq!(backend.name(), "anthropic");
            assert!(backend.supports(BackendCapability::SystemPrompt));
            assert!(backend.supports(BackendCapability::PromptCaching));
        }
    }

    #[cfg(feature = "backend-ollama")]
    mod ollama {
        use std::time::Duration;

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        use crate::{
            backend::LlmBackend,
            error::LlmError,
            ollama::{OllamaBackend, OllamaConfig},
            types::{CompletionRequest, Message},
        };

        /// Minimal one-shot HTTP/1.1 server: accept one connection, read the
        /// request head, reply with `status` and `body`, then close.
        async fn one_shot(status_line: &'static str, body: String) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                }
            });
            format!("http://{addr}")
        }

        fn backend_at(url: String, max_bytes: Option<usize>) -> OllamaBackend {
            OllamaBackend::new(OllamaConfig {
                base_url: Some(url),
                timeout: Some(Duration::from_secs(5)),
                max_response_bytes: max_bytes,
            })
            .expect("valid ollama config")
        }

        fn req() -> CompletionRequest {
            CompletionRequest::new("llama3", vec![Message::user("ping")], 64)
        }

        #[tokio::test]
        async fn happy_path_decodes_response() {
            let body = r#"{"model":"llama3","message":{"role":"assistant","content":"pong"},"prompt_eval_count":3,"eval_count":1}"#;
            let url = one_shot("200 OK", body.to_owned()).await;
            let backend = backend_at(url, None);
            let resp = backend.complete(req()).await.expect("completes");
            assert_eq!(resp.text, "pong");
            assert_eq!(resp.model, "llama3");
            assert_eq!(resp.usage.output_tokens, 1);
        }

        #[tokio::test]
        async fn oversized_response_is_rejected() {
            let big = format!(r#"{{"model":"x","message":{{"content":"{}"}}}}"#, "A".repeat(5000));
            let url = one_shot("200 OK", big).await;
            let backend = backend_at(url, Some(256));
            let err = backend.complete(req()).await.expect_err("must reject");
            assert!(matches!(err, LlmError::ResponseTooLarge { .. }));
        }

        #[tokio::test]
        async fn server_error_status_is_surfaced() {
            let url = one_shot("500 Internal Server Error", "boom".to_owned()).await;
            let backend = backend_at(url, None);
            let err = backend.complete(req()).await.expect_err("must error");
            assert!(matches!(err, LlmError::Status { status: 500, .. }));
        }

        #[test]
        fn rejects_bad_scheme() {
            let r = OllamaBackend::new(OllamaConfig {
                base_url: Some("ftp://nope".to_owned()),
                timeout: None,
                max_response_bytes: None,
            });
            assert!(matches!(r, Err(LlmError::InvalidConfig(_))));
        }
    }

    #[test]
    fn capability_is_copy_and_eq() {
        let a = BackendCapability::SystemPrompt;
        let b = a;
        assert_eq!(a, b);
    }
}
