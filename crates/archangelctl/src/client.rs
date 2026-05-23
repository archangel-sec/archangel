//! Signed control-plane client (boundary A, operator side).
//!
//! Builds a `CtlBody` (per-connection monotonic `seq` + fresh OS-random
//! nonce + timestamp), signs it with the operator key, frames it, and
//! exchanges it with the daemon over the control socket. The client never
//! holds privilege; its only authority is the signature, and the daemon
//! independently re-checks everything (peer creds, signature, replay).

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use rand::RngCore as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
};

use archangel_ctl::{
    response_from_frame_body, CtlBody, CtlRequest, CtlResponse, SignedCtlEnvelope,
};

use crate::error::CtlError;

/// A connected-per-request control client.
pub struct CtlClient {
    socket_path: PathBuf,
    signing_key: SigningKey,
    seq: u64,
}

impl CtlClient {
    /// Bind a client to the daemon socket and the operator signing key.
    #[must_use]
    pub const fn new(socket_path: PathBuf, signing_key: SigningKey) -> Self {
        Self {
            socket_path,
            signing_key,
            seq: 0,
        }
    }

    /// Build the next signed, length-prefixed request frame.
    ///
    /// Pure (no I/O) so it is unit-testable: advances `seq`, draws a fresh
    /// nonce, stamps the time, signs the exact body bytes.
    pub fn next_frame(&mut self, request: CtlRequest) -> Result<Vec<u8>, CtlError> {
        self.seq = self.seq.saturating_add(1);
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let issued_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let body = CtlBody {
            seq: self.seq,
            nonce,
            issued_ms,
            request,
        };
        let env = SignedCtlEnvelope::seal(&body, &self.signing_key)
            .map_err(|e| CtlError::Key(format!("seal control request: {e}")))?;
        env.to_frame()
            .map_err(|e| CtlError::Key(format!("frame control request: {e}")))
    }

    /// Send one request and await the daemon's response.
    pub async fn request(&mut self, request: CtlRequest) -> Result<CtlResponse, CtlError> {
        let frame = self.next_frame(request)?;
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        stream.write_all(&frame).await?;
        stream.flush().await?;

        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).await?;
        let len = SignedCtlEnvelope::frame_len(prefix)
            .map_err(|e| CtlError::Key(format!("response frame length: {e}")))?;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        response_from_frame_body(&body)
            .map_err(|e| CtlError::Key(format!("decode control response: {e}")))
    }

    /// The operator public key the daemon must be configured to trust.
    #[must_use]
    pub fn operator_public_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for &b in self.signing_key.verifying_key().as_bytes() {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use ed25519_dalek::SigningKey;

    use archangel_ctl::{CtlRequest, SignedCtlEnvelope};

    use super::CtlClient;

    fn client() -> CtlClient {
        CtlClient::new(
            "/tmp/does-not-matter.sock".into(),
            SigningKey::from_bytes(&[5u8; 32]),
        )
    }

    #[test]
    fn frame_round_trips_and_verifies_under_operator_key() {
        let mut c = client();
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let frame = c.next_frame(CtlRequest::Ping).expect("build frame");
        let env = SignedCtlEnvelope::from_frame_body(frame.get(4..).expect("body"))
            .expect("decode envelope");
        let body = env.open(&vk).expect("verify under operator key");
        assert_eq!(body.seq, 1);
        assert_eq!(body.request, CtlRequest::Ping);
    }

    #[test]
    fn seq_strictly_increases_and_nonces_differ() {
        let mut c = client();
        let vk = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let f1 = c.next_frame(CtlRequest::Ping).expect("f1");
        let f2 = c.next_frame(CtlRequest::Ping).expect("f2");
        let b1 = SignedCtlEnvelope::from_frame_body(f1.get(4..).expect("b"))
            .expect("d1")
            .open(&vk)
            .expect("o1");
        let b2 = SignedCtlEnvelope::from_frame_body(f2.get(4..).expect("b"))
            .expect("d2")
            .open(&vk)
            .expect("o2");
        assert_eq!((b1.seq, b2.seq), (1, 2));
        assert_ne!(b1.nonce, b2.nonce);
    }

    #[test]
    fn foreign_key_cannot_verify_clients_frame() {
        let mut c = client();
        let attacker = SigningKey::from_bytes(&[6u8; 32]).verifying_key();
        let frame = c.next_frame(CtlRequest::Ping).expect("frame");
        let env = SignedCtlEnvelope::from_frame_body(frame.get(4..).expect("b")).expect("decode");
        assert!(env.open(&attacker).is_err());
    }

    #[test]
    fn operator_public_hex_is_64_chars() {
        assert_eq!(client().operator_public_hex().len(), 64);
    }
}
