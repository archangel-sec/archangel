//! Minimal, allocation-light hex encoding/decoding.
//!
//! Kept local to this crate (rather than shared) to avoid widening the
//! `archangel-core` public API for an internal helper. The logic is small
//! and security-sensitive; duplicating it here keeps the audit crate's
//! trusted surface self-contained and auditable.
//!
//! These helpers are deliberately crate-private (`pub(crate)`); the
//! `redundant_pub_crate` nursery lint conflicts with `unreachable_pub`
//! here, and explicit `pub(crate)` documents the intended visibility.
#![allow(clippy::redundant_pub_crate)]

use crate::error::AuditError;

/// Encode bytes as a lowercase hex string.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        // 0..=15 always maps to a valid radix-16 digit; fallback is unreachable.
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// Decode a lowercase/uppercase hex string into bytes.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, AuditError> {
    let raw = s.as_bytes();
    let chunks = raw.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(AuditError::Hex(format!(
            "odd-length hex string ({} chars)",
            raw.len()
        )));
    }
    let mut out = Vec::new();
    for pair in raw.chunks_exact(2) {
        let hi = pair
            .first()
            .copied()
            .ok_or_else(|| AuditError::Hex("truncated hex pair".into()))
            .and_then(nibble)?;
        let lo = pair
            .get(1)
            .copied()
            .ok_or_else(|| AuditError::Hex("truncated hex pair".into()))
            .and_then(nibble)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, AuditError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(AuditError::Hex(format!(
            "invalid hex character '{}'",
            char::from(b)
        ))),
    }
}
