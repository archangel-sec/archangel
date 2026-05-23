//! Signed request/response protocol for **trust boundary B**
//! (`archangeld` T3 → `archangel-execd` T2).
//!
//! Threat model §3–§4: the daemon is *lower trust* than the executor. A
//! breach of `archangeld` must not grant the ability to mutate the system,
//! because every request crossing this boundary must carry a valid
//! Ed25519 signature from the current per-session key, and the executor
//! re-verifies everything (signature, version, replay counter, and — at a
//! higher layer — the denylist, allowlist, and `.exec` bundle signature).
//!
//! This crate is deliberately small and I/O-free: it defines the wire
//! types, the sign/verify of the envelope over the **exact** transmitted
//! bytes, and pure framing helpers. The socket accept loop, peer-credential
//! check, and replay state live in `archangel-execd` (the enforcing TCB).
//!
//! Wire format (architecture §4.2): length-prefixed CBOR frames; versioned,
//! signed envelope; monotonic per-session counter + nonce for replay
//! protection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The signed, versioned envelope and length-prefixed framing.
pub mod envelope;
/// Error types.
pub mod error;
/// Request/response message types.
pub mod message;

pub use envelope::{
    response_from_frame_body, response_to_frame, SignedEnvelope, MAX_FRAME_LEN, PROTOCOL_VERSION,
};
pub use error::IpcError;
pub use message::{ExecOutcome, ExecRequest, ExecResponse, RejectStage};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;

    use archangel_core::{ActionId, OperationMode, RiskLevel, SessionId};

    use super::{
        envelope::{SignedEnvelope, PROTOCOL_VERSION},
        message::ExecRequest,
        IpcError,
    };

    fn sample_request() -> ExecRequest {
        let mut args = BTreeMap::new();
        args.insert("service".to_owned(), "nginx.service".to_owned());
        ExecRequest {
            session_id: SessionId::new(),
            action_id: ActionId::new(),
            seq: 1,
            nonce: [7u8; 16],
            issued_ms: 1_700_000_000_000,
            profile: "default".to_owned(),
            mode: OperationMode::ReadOnly,
            exec_name: "read-logs".to_owned(),
            args,
            declared_risk: RiskLevel::Low,
            declared_read_only: true,
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn seal_then_open_round_trips() {
        let sk = key(1);
        let req = sample_request();
        let env = SignedEnvelope::seal(&req, &sk).expect("seal");
        let opened = env.open(&sk.verifying_key()).expect("open");
        assert_eq!(opened, req);
    }

    #[test]
    fn wrong_session_key_is_rejected() {
        let sk = key(1);
        let env = SignedEnvelope::seal(&sample_request(), &sk).expect("seal");
        let attacker = key(2);
        assert!(matches!(
            env.open(&attacker.verifying_key()),
            Err(IpcError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_request_bytes_break_signature() {
        let sk = key(1);
        let mut env = SignedEnvelope::seal(&sample_request(), &sk).expect("seal");
        // Flip a byte in the signed payload.
        if let Some(b) = env.request.get_mut(4) {
            *b ^= 0xff;
        }
        assert!(matches!(
            env.open(&sk.verifying_key()),
            Err(IpcError::SignatureInvalid)
        ));
    }

    #[test]
    fn version_mismatch_is_rejected_before_decode() {
        let sk = key(1);
        let mut env = SignedEnvelope::seal(&sample_request(), &sk).expect("seal");
        env.version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            env.open(&sk.verifying_key()),
            Err(IpcError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn bad_signature_length_is_rejected() {
        let sk = key(1);
        let mut env = SignedEnvelope::seal(&sample_request(), &sk).expect("seal");
        env.signature.truncate(10);
        assert!(matches!(
            env.open(&sk.verifying_key()),
            Err(IpcError::BadSignatureLen(10))
        ));
    }

    #[test]
    fn frame_round_trip() {
        let sk = key(1);
        let req = sample_request();
        let env = SignedEnvelope::seal(&req, &sk).expect("seal");
        let frame = env.to_frame().expect("frame");
        let prefix: [u8; 4] = frame.get(..4).expect("prefix").try_into().expect("4");
        let len = SignedEnvelope::frame_len(prefix).expect("len");
        let body = frame.get(4..4 + len).expect("body");
        let decoded = SignedEnvelope::from_frame_body(body).expect("decode");
        assert_eq!(decoded, env);
        assert_eq!(decoded.open(&sk.verifying_key()).expect("open"), req);
    }

    #[test]
    fn oversized_frame_prefix_is_rejected_before_alloc() {
        let huge = u32::MAX.to_be_bytes();
        assert!(matches!(
            SignedEnvelope::frame_len(huge),
            Err(IpcError::Framing(_))
        ));
    }
}
