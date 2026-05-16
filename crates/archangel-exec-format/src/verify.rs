//! Signature verification and the [`VerifiedBundle`] typestate.
//!
//! # Authenticate before processing
//!
//! Order is load-bearing and not negotiable:
//!
//! 1. Verify the detached Ed25519 signature over the **exact bytes** of the
//!    `.exec` file, against the operator trust set.
//! 2. Only then parse the TOML manifest.
//! 3. Then check that the payload's SHA-256 matches the (now authenticated)
//!    manifest.
//!
//! TOML parsing is attack surface; we do as little as possible with bytes we
//! have not yet authenticated. The signature covers the raw file bytes the
//! operator actually signed — never a re-serialized form, which would not be
//! canonical.
//!
//! # Unforgeable
//!
//! [`VerifiedBundle`] has no public constructor and does not implement
//! `Deserialize`. The only way to obtain one is to go through verification.
//! This makes "an unverified bundle reached the executor" a compile error,
//! not a code-review hope.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    error::ExecFormatError, hex, manifest::ExecManifest, trust::OperatorTrust,
};

/// A `.exec` bundle whose signature and payload hash have been verified.
///
/// Holding a value of this type is proof that:
/// - a trusted operator key signed the exact manifest bytes, and
/// - the payload matches the SHA-256 in that signed manifest.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    manifest: ExecManifest,
}

impl VerifiedBundle {
    /// Verify a bundle from in-memory bytes.
    ///
    /// `manifest_bytes` is the raw `.exec` file content. `signature_text`
    /// is the `.exec.sig` content: hex of a 64-byte Ed25519 signature.
    pub fn verify_bytes(
        manifest_bytes: &[u8],
        signature_text: &str,
        trust: &OperatorTrust,
    ) -> Result<Self, ExecFormatError> {
        // (1) Signature first, over the exact file bytes.
        let sig = parse_signature(signature_text)?;
        let authenticated = trust
            .keys()
            .iter()
            .any(|key: &VerifyingKey| key.verify_strict(manifest_bytes, &sig).is_ok());
        if !authenticated {
            return Err(ExecFormatError::Untrusted);
        }

        // (2) Now it is safe(r) to parse.
        let manifest = ExecManifest::parse(manifest_bytes)?;

        // (3) Bind the payload to the signed manifest.
        verify_payload_hash(&manifest)?;

        Ok(Self { manifest })
    }

    /// Verify a bundle from files: `exec_path` and its detached
    /// `signature_path` (conventionally `<exec_path>.sig`).
    pub fn load(
        exec_path: &std::path::Path,
        signature_path: &std::path::Path,
        trust: &OperatorTrust,
    ) -> Result<Self, ExecFormatError> {
        let manifest_bytes = std::fs::read(exec_path)?;
        let signature_text = std::fs::read_to_string(signature_path)?;
        Self::verify_bytes(&manifest_bytes, &signature_text, trust)
    }

    /// The authenticated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ExecManifest {
        &self.manifest
    }

    /// Validate LLM-proposed argument values against this bundle's declared
    /// schema (layer #7). Only verified bundles can have args validated —
    /// that ordering is guaranteed by this method living on the typestate.
    pub fn validate_args(
        &self,
        provided: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), ExecFormatError> {
        crate::args::validate(&self.manifest, provided)
    }
}

fn parse_signature(signature_text: &str) -> Result<Signature, ExecFormatError> {
    let bytes = hex::decode(signature_text).map_err(ExecFormatError::BadSignature)?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ExecFormatError::BadSignature("signature is not 64 bytes".to_owned()))?;
    Ok(Signature::from_bytes(&arr))
}

fn verify_payload_hash(manifest: &ExecManifest) -> Result<(), ExecFormatError> {
    let digest: [u8; 32] = Sha256::digest(manifest.payload.inline.as_bytes()).into();
    let actual = hex::encode(&digest);
    let declared = manifest.payload.sha256.trim().to_ascii_lowercase();
    if actual == declared {
        Ok(())
    } else {
        Err(ExecFormatError::PayloadHashMismatch {
            declared,
            actual,
        })
    }
}
