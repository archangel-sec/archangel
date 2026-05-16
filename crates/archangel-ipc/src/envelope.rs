//! The signed envelope and length-prefixed framing for boundary B.
//!
//! # Sign the exact bytes
//!
//! The signature covers the **exact CBOR bytes** of the encoded
//! `ExecRequest` that travel on the wire — never a re-encoded form. The
//! verifier checks the signature against those received bytes and only then
//! decodes them. This is the same principle the `.exec` verifier uses
//! (`archangel-exec-format`): authenticate first, parse second, and never
//! depend on encoder determinism for security.
//!
//! # Framing
//!
//! Stream sockets have no message boundaries, so each envelope is sent as a
//! 4-byte big-endian length prefix followed by that many CBOR bytes. A hard
//! cap rejects absurd lengths before allocation (a hostile/buggy peer must
//! not be able to make the executor allocate unbounded memory).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{error::IpcError, message::ExecRequest};

/// Protocol version this build speaks. Bump on any wire-format change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap on a single frame (1 MiB). Requests are tiny; this only exists
/// to bound a hostile peer's influence on executor memory.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// A signed, versioned request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// Protocol version.
    pub version: u16,
    /// CBOR-encoded [`ExecRequest`] — the exact bytes that were signed.
    pub request: Vec<u8>,
    /// Ed25519 signature (64 bytes) over `request`.
    pub signature: Vec<u8>,
}

fn cbor_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, IpcError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| IpcError::Codec(e.to_string()))?;
    Ok(buf)
}

fn cbor_from_slice<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, IpcError> {
    ciborium::from_reader(bytes).map_err(|e| IpcError::Codec(e.to_string()))
}

impl SignedEnvelope {
    /// Seal a request: CBOR-encode it, sign those exact bytes with the
    /// per-session signing key, and wrap in a versioned envelope.
    pub fn seal(
        request: &ExecRequest,
        signing_key: &SigningKey,
    ) -> Result<Self, IpcError> {
        let request_bytes = cbor_to_vec(request)?;
        let signature = signing_key.sign(&request_bytes).to_bytes().to_vec();
        Ok(Self {
            version: PROTOCOL_VERSION,
            request: request_bytes,
            signature,
        })
    }

    /// Verify version + signature against the session verifying key, then
    /// decode the request. The decode happens **only after** the signature
    /// is proven valid.
    pub fn open(&self, verifying_key: &VerifyingKey) -> Result<ExecRequest, IpcError> {
        if self.version != PROTOCOL_VERSION {
            return Err(IpcError::VersionMismatch {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| IpcError::BadSignatureLen(self.signature.len()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(&self.request, &signature)
            .map_err(|_| IpcError::SignatureInvalid)?;
        cbor_from_slice(&self.request)
    }

    /// Encode this envelope as a length-prefixed frame ready for a socket.
    pub fn to_frame(&self) -> Result<Vec<u8>, IpcError> {
        let body = cbor_to_vec(self)?;
        if body.len() > MAX_FRAME_LEN {
            return Err(IpcError::Framing(format!(
                "frame of {} bytes exceeds cap {MAX_FRAME_LEN}",
                body.len()
            )));
        }
        let len = u32::try_from(body.len())
            .map_err(|_| IpcError::Framing("frame length overflows u32".to_owned()))?;
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Parse the declared body length from a 4-byte big-endian prefix,
    /// rejecting anything over [`MAX_FRAME_LEN`] before allocation.
    pub fn frame_len(prefix: [u8; 4]) -> Result<usize, IpcError> {
        let len = u32::from_be_bytes(prefix) as usize;
        if len > MAX_FRAME_LEN {
            return Err(IpcError::Framing(format!(
                "declared frame length {len} exceeds cap {MAX_FRAME_LEN}"
            )));
        }
        Ok(len)
    }

    /// Decode an envelope from a frame body (the bytes after the prefix).
    pub fn from_frame_body(body: &[u8]) -> Result<Self, IpcError> {
        cbor_from_slice(body)
    }
}

/// Encode an [`ExecResponse`] as a length-prefixed frame.
///
/// Responses are not signed in v0.1: the local socket is peer-credential
/// authenticated and the reply goes back to the already-authenticated
/// daemon. Mutual signing is later hardening.
pub fn response_to_frame(
    response: &crate::message::ExecResponse,
) -> Result<Vec<u8>, IpcError> {
    let body = cbor_to_vec(response)?;
    let len = u32::try_from(body.len())
        .map_err(|_| IpcError::Framing("response too large".to_owned()))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode an [`ExecResponse`] from a frame body.
pub fn response_from_frame_body(
    body: &[u8],
) -> Result<crate::message::ExecResponse, IpcError> {
    cbor_from_slice(body)
}
