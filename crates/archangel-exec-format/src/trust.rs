//! Operator trust set: the Ed25519 public keys whose signatures make a
//! `.exec` bundle trustworthy.
//!
//! Loaded from `/etc/archangel/trust/operators.pubkeys`. Format: one key
//! per line as 64 hex chars (32-byte Ed25519 public key), optionally
//! followed by whitespace and a free-form label. Blank lines and lines
//! beginning with `#` are ignored.
//!
//! An empty trust set is **valid and means "trust nobody"** — every bundle
//! is then rejected. That is the correct fail-closed posture, not an error.

use std::str::FromStr;

use ed25519_dalek::VerifyingKey;

use crate::{error::ExecFormatError, hex};

/// A set of trusted operator public keys.
#[derive(Debug, Clone, Default)]
pub struct OperatorTrust {
    keys: Vec<VerifyingKey>,
}

impl FromStr for OperatorTrust {
    type Err = ExecFormatError;

    /// Parse a trust set from the `operators.pubkeys` text format.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut keys = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let hex_part = line.split_whitespace().next().unwrap_or(line);
            let bytes = hex::decode(hex_part)
                .map_err(|e| ExecFormatError::BadTrustFile(format!("line {}: {e}", lineno + 1)))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                ExecFormatError::BadTrustFile(format!("line {}: key is not 32 bytes", lineno + 1))
            })?;
            let key = VerifyingKey::from_bytes(&arr).map_err(|e| {
                ExecFormatError::BadTrustFile(format!(
                    "line {}: invalid Ed25519 key: {e}",
                    lineno + 1
                ))
            })?;
            keys.push(key);
        }
        Ok(Self { keys })
    }
}

impl OperatorTrust {
    /// Load a trust set from a file.
    pub fn load(path: &std::path::Path) -> Result<Self, ExecFormatError> {
        let text = std::fs::read_to_string(path)?;
        text.parse()
    }

    /// Number of trusted keys. Zero means "trust nobody" (all bundles fail).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the trust set is empty (trusts nobody).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The trusted keys, for the verifier to try in turn.
    pub(crate) fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }
}
