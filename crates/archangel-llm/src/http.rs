//! Hardened HTTP client shared by network backends.
//!
//! Every control here exists for a specific threat:
//!
//! - **No redirects.** A compromised or hijacked endpoint must not be able
//!   to 3xx a request that carries the API key onto an attacker host.
//! - **No environment proxy.** `HTTP(S)_PROXY` in the daemon's environment
//!   must not silently route inference (and the key) through a MITM.
//! - **Mandatory timeouts.** A hung backend cannot wedge the daemon.
//! - **rustls only.** No OpenSSL in the trust path (workspace-enforced).
//! - **TLS required for remote endpoints.** Plaintext inference to a remote
//!   host is refused before any byte is sent.
//! - **Response size cap.** A buggy/hostile endpoint cannot stream an
//!   unbounded body to exhaust memory; we stop reading past the cap.
//!
//! `pub(crate)` here is intentional (the helpers are crate-internal);
//! `redundant_pub_crate` conflicts with `unreachable_pub` for a private
//! module, so the explicit visibility is documented and allowed.
#![allow(clippy::redundant_pub_crate)]

use std::time::Duration;

use crate::error::LlmError;

/// Connection-phase timeout. Deliberately shorter than the overall timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a hardened [`reqwest::Client`].
///
/// `require_tls` is `true` for remote backends (Anthropic) and `false`
/// only for explicitly-local backends (Ollama on loopback).
pub(crate) fn build_client(
    require_tls: bool,
    overall_timeout: Duration,
) -> Result<reqwest::Client, LlmError> {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(overall_timeout)
        .user_agent(concat!("archangel/", env!("CARGO_PKG_VERSION")))
        .https_only(require_tls);

    builder
        .build()
        .map_err(|e| LlmError::InvalidConfig(format!("could not build HTTP client: {e}")))
}

/// Send a prepared request, enforce the status, and return the body read
/// under a hard byte cap.
pub(crate) async fn send_capped(
    request: reqwest::RequestBuilder,
    max_bytes: usize,
) -> Result<Vec<u8>, LlmError> {
    let mut response = request
        .send()
        .await
        .map_err(|e| LlmError::Transport(redact(&e)))?;

    let status = response.status();

    // Refuse before downloading if the endpoint announces an oversized body.
    if let Some(len) = response.content_length() {
        if usize::try_from(len).unwrap_or(usize::MAX) > max_bytes {
            return Err(LlmError::ResponseTooLarge { max_bytes });
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| LlmError::Transport(redact(&e)))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(LlmError::ResponseTooLarge { max_bytes });
        }
        body.extend_from_slice(&chunk);
    }

    if !status.is_success() {
        return Err(LlmError::Status {
            status: status.as_u16(),
            snippet: snippet(&body),
        });
    }

    Ok(body)
}

/// reqwest's `Display` does not include headers (so never the API key), but
/// it can include the URL. That is acceptable to surface; we still keep the
/// message short to avoid noisy logs.
fn redact(e: &reqwest::Error) -> String {
    let s = e.to_string();
    snippet(s.as_bytes())
}

/// A short, lossy, printable snippet for diagnostics.
fn snippet(bytes: &[u8]) -> String {
    const MAX: usize = 256;
    let take = bytes.len().min(MAX);
    let shown = String::from_utf8_lossy(bytes.get(..take).unwrap_or(bytes));
    if bytes.len() > MAX {
        format!("{shown}…")
    } else {
        shown.into_owned()
    }
}
