//! Per-session identity and the daemon side of trust boundary B.
//!
//! Each session has an **ephemeral** Ed25519 key. Its public half is handed
//! to `archangel-execd` out of band at session start (architecture §4.2:
//! "rotated on each `archangeld` restart"); its private half lives only in
//! this process's memory and zeroizes on drop (ed25519-dalek `zeroize`
//! feature). Every `ExecRequest` is signed with it and carries a strictly
//! increasing per-session `seq` plus a fresh random nonce, so the executor
//! can reject replays and reordering.
//!
//! A breach of `archangeld` is still contained: the attacker would have to
//! also defeat the executor's independent re-validation (denylist,
//! allowlist, signed `.exec` bundle, read-only enforcement). The signature
//! only proves "the current daemon asked"; it does not grant trust.

use std::{
    collections::BTreeMap,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore as _;

use archangel_core::{ActionId, OperationMode, RiskLevel, SessionId};
use archangel_ipc::{ExecRequest, IpcError, SignedEnvelope};

/// A live operator session.
pub struct Session {
    id: SessionId,
    signing_key: SigningKey,
    mode: OperationMode,
    profile: String,
    seq: u64,
}

impl Session {
    /// Start a new session: fresh id and fresh ephemeral signing key.
    #[must_use]
    pub fn new(mode: OperationMode, profile: impl Into<String>) -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self {
            id: SessionId::new(),
            signing_key: SigningKey::generate(&mut csprng),
            mode,
            profile: profile.into(),
            seq: 0,
        }
    }

    /// The session id (appears in every audit record for the session).
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// The active mode.
    #[must_use]
    pub const fn mode(&self) -> OperationMode {
        self.mode
    }

    /// The active profile name.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The public key the executor must be told to verify this session's
    /// requests. Hand this to `archangel-execd` out of band at start.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Build and sign the next `ExecRequest` for boundary B.
    ///
    /// `seq` is advanced first and is strictly increasing; the nonce is
    /// fresh OS randomness. `declared_*` are the daemon's *claims* — the
    /// executor re-derives the truth from the signed bundle and does not
    /// trust them.
    pub fn sign_exec_request(
        &mut self,
        action_id: ActionId,
        exec_name: impl Into<String>,
        args: BTreeMap<String, String>,
        declared_risk: RiskLevel,
        declared_read_only: bool,
    ) -> Result<SignedEnvelope, IpcError> {
        self.seq = self.seq.saturating_add(1);

        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let issued_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

        let request = ExecRequest {
            session_id: self.id,
            action_id,
            seq: self.seq,
            nonce,
            issued_ms,
            profile: self.profile.clone(),
            mode: self.mode,
            exec_name: exec_name.into(),
            args,
            declared_risk,
            declared_read_only,
        };
        SignedEnvelope::seal(&request, &self.signing_key)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("mode", &self.mode)
            .field("profile", &self.profile)
            .field("seq", &self.seq)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use archangel_core::{ActionId, OperationMode, RiskLevel};

    use super::Session;

    fn sign(s: &mut Session) -> archangel_ipc::ExecRequest {
        let env = s
            .sign_exec_request(
                ActionId::new(),
                "read-logs",
                BTreeMap::new(),
                RiskLevel::Low,
                true,
            )
            .expect("seal");
        env.open(&s.verifying_key()).expect("open")
    }

    #[test]
    fn new_sessions_are_distinct() {
        let a = Session::new(OperationMode::ReadOnly, "default");
        let b = Session::new(OperationMode::ReadOnly, "default");
        assert_ne!(a.id(), b.id());
        assert_ne!(a.verifying_key().as_bytes(), b.verifying_key().as_bytes());
    }

    #[test]
    fn seq_is_strictly_increasing_and_nonces_differ() {
        let mut s = Session::new(OperationMode::ReadOnly, "ops");
        let r1 = sign(&mut s);
        let r2 = sign(&mut s);
        let r3 = sign(&mut s);
        assert_eq!((r1.seq, r2.seq, r3.seq), (1, 2, 3));
        assert_ne!(r1.nonce, r2.nonce);
        assert_ne!(r2.nonce, r3.nonce);
        assert_eq!(r1.session_id, s.id());
        assert_eq!(r1.profile, "ops");
        assert_eq!(r1.mode, OperationMode::ReadOnly);
    }

    #[test]
    fn signature_only_verifies_under_its_own_session_key() {
        let mut s = Session::new(OperationMode::ReadOnly, "default");
        let other = Session::new(OperationMode::ReadOnly, "default");
        let env = s
            .sign_exec_request(
                ActionId::new(),
                "read-logs",
                BTreeMap::new(),
                RiskLevel::Low,
                true,
            )
            .expect("seal");
        assert!(env.open(&s.verifying_key()).is_ok());
        assert!(
            env.open(&other.verifying_key()).is_err(),
            "a different session's key must not verify this request"
        );
    }

    #[test]
    fn debug_does_not_leak_signing_key() {
        let s = Session::new(OperationMode::ReadOnly, "default");
        assert!(format!("{s:?}").contains("REDACTED"));
    }
}
