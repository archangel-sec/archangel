//! Ed25519 key handling for the audit log.
//!
//! The signing key (asset A4-adjacent) never leaves this wrapper except as
//! a [`SecretBytes`], which zeroes itself on drop. `ed25519_dalek::SigningKey`
//! also zeroizes its own memory on drop (the `zeroize` feature is enabled in
//! the workspace), so the secret scalar is never left in freed memory.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use archangel_core::SecretBytes;

use crate::{error::AuditError, hex};

/// An Ed25519 keypair used to sign audit entries.
pub struct AuditKeypair {
    signing: SigningKey,
}

impl AuditKeypair {
    /// Generate a fresh keypair from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut csprng),
        }
    }

    /// Reconstruct a keypair from a 32-byte secret seed.
    #[must_use]
    pub fn from_secret_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Reconstruct a keypair from a hex-encoded 32-byte secret seed.
    pub fn from_secret_hex(seed_hex: &str) -> Result<Self, AuditError> {
        let raw = hex::decode(seed_hex)?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| AuditError::Crypto("secret seed must be 32 bytes".into()))?;
        Ok(Self::from_secret_bytes(&seed))
    }

    /// Export the 32-byte secret seed inside a zeroizing container.
    ///
    /// Handle the result as briefly as possible and never log it.
    #[must_use]
    pub fn secret_bytes(&self) -> SecretBytes {
        SecretBytes::new(self.signing.to_bytes().to_vec())
    }

    /// The public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The public verifying key, hex-encoded (32 bytes → 64 hex chars).
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    /// Sign a message, returning the 64-byte signature.
    #[must_use]
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Parse a hex-encoded 32-byte Ed25519 public key.
pub fn verifying_key_from_hex(public_hex: &str) -> Result<VerifyingKey, AuditError> {
    let raw = hex::decode(public_hex)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| AuditError::Crypto("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| AuditError::Crypto(format!("invalid Ed25519 public key: {e}")))
}
