//! Signed control envelope + length-prefixed framing for boundary A.
//!
//! Same proven discipline as `archangel-ipc` (boundary B): the operator
//! signs the **exact CBOR bytes** of the request body; the daemon verifies
//! the signature against those received bytes and only then decodes
//! (authenticate-before-parse, never trust encoder determinism). The body
//! carries a per-connection monotonic `seq` and a random `nonce` so the
//! daemon can reject replays/reorders. Frames are length-prefixed CBOR with
//! a hard pre-allocation cap.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{error::CtlError, message::CtlRequest};

/// Control protocol version. Bump on any wire-format change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap on a single frame (1 MiB). Control messages are small; this
/// only bounds a hostile/buggy peer's influence on daemon memory.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// The signed body: the request plus replay metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlBody {
    /// Per-connection monotonic counter (daemon rejects non-increasing).
    pub seq: u64,
    /// Per-request random nonce (defense in depth alongside `seq`).
    pub nonce: [u8; 16],
    /// Milliseconds since the Unix epoch when issued (lets the daemon
    /// expire stale requests).
    pub issued_ms: u64,
    /// The actual request.
    pub request: CtlRequest,
}

/// A signed, versioned control envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCtlEnvelope {
    /// Protocol version.
    pub version: u16,
    /// CBOR-encoded [`CtlBody`] — the exact bytes that were signed.
    pub body: Vec<u8>,
    /// Ed25519 signature (64 bytes) over `body`.
    pub signature: Vec<u8>,
}

fn cbor_to_vec<T: Serialize>(v: &T) -> Result<Vec<u8>, CtlError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|e| CtlError::Codec(e.to_string()))?;
    Ok(buf)
}

fn cbor_from_slice<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T, CtlError> {
    ciborium::from_reader(b).map_err(|e| CtlError::Codec(e.to_string()))
}

impl SignedCtlEnvelope {
    /// Seal a request: CBOR-encode the body, sign those exact bytes with
    /// the operator's signing key, wrap in a versioned envelope.
    pub fn seal(body: &CtlBody, operator_key: &SigningKey) -> Result<Self, CtlError> {
        let body_bytes = cbor_to_vec(body)?;
        let signature = operator_key.sign(&body_bytes).to_bytes().to_vec();
        Ok(Self {
            version: PROTOCOL_VERSION,
            body: body_bytes,
            signature,
        })
    }

    /// Verify version + signature against the trusted operator key, then
    /// decode the body. Decode happens only after the signature is proven.
    pub fn open(&self, operator_pub: &VerifyingKey) -> Result<CtlBody, CtlError> {
        if self.version != PROTOCOL_VERSION {
            return Err(CtlError::VersionMismatch {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CtlError::BadSignatureLen(self.signature.len()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        operator_pub
            .verify_strict(&self.body, &signature)
            .map_err(|_| CtlError::SignatureInvalid)?;
        cbor_from_slice(&self.body)
    }

    /// Encode as a length-prefixed frame.
    pub fn to_frame(&self) -> Result<Vec<u8>, CtlError> {
        let body = cbor_to_vec(self)?;
        if body.len() > MAX_FRAME_LEN {
            return Err(CtlError::Framing(format!(
                "frame of {} bytes exceeds cap {MAX_FRAME_LEN}",
                body.len()
            )));
        }
        let len = u32::try_from(body.len())
            .map_err(|_| CtlError::Framing("frame length overflows u32".to_owned()))?;
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Parse the declared body length from a 4-byte big-endian prefix,
    /// rejecting oversized frames before allocation.
    pub fn frame_len(prefix: [u8; 4]) -> Result<usize, CtlError> {
        let len = u32::from_be_bytes(prefix) as usize;
        if len > MAX_FRAME_LEN {
            return Err(CtlError::Framing(format!(
                "declared frame length {len} exceeds cap {MAX_FRAME_LEN}"
            )));
        }
        Ok(len)
    }

    /// Decode an envelope from a frame body (bytes after the prefix).
    pub fn from_frame_body(body: &[u8]) -> Result<Self, CtlError> {
        cbor_from_slice(body)
    }
}

/// Encode a [`crate::CtlResponse`] as a length-prefixed frame.
///
/// Responses are not signed in v0.1: the local socket is peer-credential
/// authenticated and the reply goes back to the already-authenticated
/// operator connection. Mutual signing is later hardening.
pub fn response_to_frame(response: &crate::message::CtlResponse) -> Result<Vec<u8>, CtlError> {
    let body = cbor_to_vec(response)?;
    let len = u32::try_from(body.len())
        .map_err(|_| CtlError::Framing("response too large".to_owned()))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode a [`crate::CtlResponse`] from a frame body.
pub fn response_from_frame_body(body: &[u8]) -> Result<crate::message::CtlResponse, CtlError> {
    cbor_from_slice(body)
}
