//! Typed 128-bit identifiers for sessions and actions.
//!
//! Both types are 16 bytes of OS randomness displayed as 32 lowercase hex
//! characters. They are **not secret** — they appear in audit records and
//! log lines — but must be unguessable to prevent replay or cross-session
//! confusion.

use std::{fmt, str::FromStr};

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Parse a 32-character lowercase/uppercase hex string into a 16-byte array.
fn parse_hex16(s: &str) -> Result<[u8; 16], CoreError> {
    let src = s.as_bytes();
    if src.len() != 32 {
        return Err(CoreError::InvalidId(format!(
            "expected 32 hex chars, got {}",
            src.len()
        )));
    }
    let mut out = [0u8; 16];
    let mut iter = src.iter().copied();
    for slot in &mut out {
        let hi = iter
            .next()
            .ok_or_else(|| CoreError::InvalidId("truncated hex string".into()))
            .and_then(hex_nibble)?;
        let lo = iter
            .next()
            .ok_or_else(|| CoreError::InvalidId("truncated hex string".into()))
            .and_then(hex_nibble)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, CoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(CoreError::InvalidId(format!(
            "invalid hex character '{}'",
            char::from(b)
        ))),
    }
}

// ── macro ─────────────────────────────────────────────────────────────────────

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Generate a cryptographically random id using OS entropy.
            #[must_use]
            pub fn new() -> Self {
                let mut bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Construct from a known byte array (e.g. deserialized from storage).
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Return the underlying bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl FromStr for $name {
            type Err = CoreError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_hex16(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                parse_hex16(&raw).map(Self).map_err(serde::de::Error::custom)
            }
        }
    };
}

// ── types ─────────────────────────────────────────────────────────────────────

define_id!(
    /// Unique identifier for a single interactive session with the LLM.
    ///
    /// Generated fresh at session start. Included in every audit record
    /// produced during the session to allow filtering and correlation.
    SessionId
);

define_id!(
    /// Unique identifier for a single action proposed or executed during a session.
    ///
    /// Links the proposal, the policy decision, the sandbox execution, and the
    /// outcome record in the audit log into a single traceable unit.
    ActionId
);

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{ActionId, SessionId};

    #[test]
    fn session_id_display_is_32_hex_chars() {
        let id = SessionId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_id_round_trip() -> Result<(), crate::CoreError> {
        let id = SessionId::new();
        let parsed = id.to_string().parse::<SessionId>()?;
        assert_eq!(id, parsed);
        Ok(())
    }

    #[test]
    fn session_id_rejects_short_string() {
        assert!("abc".parse::<SessionId>().is_err());
    }

    #[test]
    fn session_id_rejects_invalid_hex() {
        assert!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            .parse::<SessionId>()
            .is_err());
    }

    #[test]
    fn two_new_ids_differ() {
        // Probability of collision is 1/2^128 — negligible.
        assert_ne!(SessionId::new(), SessionId::new());
    }

    #[test]
    fn action_id_round_trip() -> Result<(), crate::CoreError> {
        let id = ActionId::new();
        let parsed = id.to_string().parse::<ActionId>()?;
        assert_eq!(id, parsed);
        Ok(())
    }
}
