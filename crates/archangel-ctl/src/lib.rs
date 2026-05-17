//! Signed control-plane protocol for **trust boundary A**
//! (operator `archangelctl` → daemon `archangeld`).
//!
//! Architecture §4.1: the control socket authenticates the operator by
//! peer credentials (checked socket-side by the daemon) **and** an Ed25519
//! signature over every request, verified against the operator public key
//! created by `archangelctl init`. A request the daemon cannot prove came
//! from the trusted operator key is never acted on.
//!
//! Like `archangel-ipc` (boundary B) this crate is small and I/O-free: it
//! defines the wire types, the sign/verify of the envelope over the
//! **exact** transmitted bytes, and pure framing helpers. The socket
//! server, peer-credential check, and replay state live in the daemon.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Error types.
pub mod error;
/// The signed, versioned envelope and length-prefixed framing.
pub mod envelope;
/// Control-plane message types.
pub mod message;

pub use envelope::{
    response_from_frame_body, response_to_frame, CtlBody, SignedCtlEnvelope,
    MAX_FRAME_LEN, PROTOCOL_VERSION,
};
pub use error::CtlError;
pub use message::{CtlOutcome, CtlRequest, CtlResponse};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{
        envelope::{CtlBody, SignedCtlEnvelope, PROTOCOL_VERSION},
        message::CtlRequest,
        CtlError,
    };

    fn body() -> CtlBody {
        CtlBody {
            seq: 1,
            nonce: [3u8; 16],
            issued_ms: 1_700_000_000_000,
            request: CtlRequest::RunTask {
                task: "why is nginx down".to_owned(),
                context: vec![("journal".to_owned(), "bind() failed".to_owned())],
            },
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn seal_then_open_round_trips() {
        let k = key(1);
        let b = body();
        let env = SignedCtlEnvelope::seal(&b, &k).expect("seal");
        assert_eq!(env.open(&k.verifying_key()).expect("open"), b);
    }

    #[test]
    fn foreign_operator_key_is_rejected() {
        let env = SignedCtlEnvelope::seal(&body(), &key(1)).expect("seal");
        assert!(matches!(
            env.open(&key(2).verifying_key()),
            Err(CtlError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let k = key(1);
        let mut env = SignedCtlEnvelope::seal(&body(), &k).expect("seal");
        if let Some(x) = env.body.get_mut(3) {
            *x ^= 0xff;
        }
        assert!(matches!(
            env.open(&k.verifying_key()),
            Err(CtlError::SignatureInvalid)
        ));
    }

    #[test]
    fn version_mismatch_rejected_before_decode() {
        let k = key(1);
        let mut env = SignedCtlEnvelope::seal(&body(), &k).expect("seal");
        env.version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            env.open(&k.verifying_key()),
            Err(CtlError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn bad_signature_length_rejected() {
        let k = key(1);
        let mut env = SignedCtlEnvelope::seal(&body(), &k).expect("seal");
        env.signature.truncate(7);
        assert!(matches!(
            env.open(&k.verifying_key()),
            Err(CtlError::BadSignatureLen(7))
        ));
    }

    #[test]
    fn frame_round_trip() {
        let k = key(1);
        let b = body();
        let env = SignedCtlEnvelope::seal(&b, &k).expect("seal");
        let frame = env.to_frame().expect("frame");
        let prefix: [u8; 4] = frame.get(..4).expect("p").try_into().expect("4");
        let len = SignedCtlEnvelope::frame_len(prefix).expect("len");
        let decoded =
            SignedCtlEnvelope::from_frame_body(frame.get(4..4 + len).expect("body"))
                .expect("decode");
        assert_eq!(decoded.open(&k.verifying_key()).expect("open"), b);
    }

    #[test]
    fn oversized_frame_prefix_rejected_before_alloc() {
        assert!(matches!(
            SignedCtlEnvelope::frame_len(u32::MAX.to_be_bytes()),
            Err(CtlError::Framing(_))
        ));
    }

    #[test]
    fn response_frame_round_trips() {
        use super::message::{CtlOutcome, CtlResponse};
        let r = CtlResponse::Task(CtlOutcome::Executed {
            exec: "read-logs".to_owned(),
            exit_code: 0,
            stdout: "ok".to_owned(),
            stderr: String::new(),
        });
        let frame = super::response_to_frame(&r).expect("frame");
        let decoded =
            super::response_from_frame_body(frame.get(4..).expect("body"))
                .expect("decode");
        assert_eq!(decoded, r);
    }
}
