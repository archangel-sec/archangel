//! Minimal hex decoding (local, like in `archangel-audit`, to keep this
//! trusted crate's surface self-contained rather than widening a shared API).
#![allow(clippy::redundant_pub_crate)]

/// Encode bytes as a lowercase hex string.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// Decode a hex string (any case, optional surrounding whitespace) to bytes.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let raw = s.as_bytes();
    let chunks = raw.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(format!("odd-length hex string ({} chars)", raw.len()));
    }
    let mut out = Vec::new();
    for pair in raw.chunks_exact(2) {
        let hi = pair
            .first()
            .copied()
            .ok_or_else(|| "truncated hex pair".to_owned())
            .and_then(nibble)?;
        let lo = pair
            .get(1)
            .copied()
            .ok_or_else(|| "truncated hex pair".to_owned())
            .and_then(nibble)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(format!("invalid hex character '{}'", char::from(b))),
    }
}
