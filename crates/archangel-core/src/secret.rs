//! Zeroize-aware wrappers for secret material.
//!
//! # Security properties
//!
//! - Neither type implements [`Clone`] — copying a secret requires explicit intent.
//! - Neither type implements [`std::fmt::Display`] — accidental formatting cannot
//!   leak the value into logs or error messages.
//! - [`std::fmt::Debug`] always prints `"[REDACTED]"`.
//! - On drop, the backing allocation is overwritten with zeros before the
//!   memory is returned to the allocator (via [`zeroize::ZeroizeOnDrop`]).
//! - [`SecretBytes::ct_eq`] uses constant-time comparison to prevent timing
//!   side-channel attacks on secret values.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── SecretString ──────────────────────────────────────────────────────────────

/// A UTF-8 string that is securely zeroed when dropped.
///
/// Intended for API keys, passwords, and any textual secret material.
/// Call [`SecretString::expose_secret`] only when the raw value is required —
/// the explicit name acts as a visible marker during code review.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a string in a zeroize-aware container.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// Expose the secret value for use.
    ///
    /// The name `expose_secret` is intentional: it serves as a visible
    /// marker in code review that secret material is being accessed.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Return the byte length of the underlying string.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the string holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

// ── SecretBytes ───────────────────────────────────────────────────────────────

/// Raw bytes that are securely zeroed when dropped.
///
/// Intended for symmetric keys, HMAC secrets, tokens, and binary secret data.
/// Call [`SecretBytes::expose_secret`] only when the raw bytes are required.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap bytes in a zeroize-aware container.
    #[must_use]
    pub const fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Expose the secret bytes for use.
    ///
    /// The name `expose_secret` is intentional: it serves as a visible
    /// marker in code review that secret material is being accessed.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Compare two secrets in **constant time**, preventing timing attacks.
    ///
    /// Note: the length comparison is not constant-time. Secrets with
    /// different lengths are trivially unequal; this leaks only the fact
    /// that lengths differ, not the content of either secret.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }

    /// Return the number of bytes held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if no bytes are held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString};

    #[test]
    fn secret_string_debug_does_not_leak() {
        let s = SecretString::from("my-api-key-12345");
        let debug = format!("{s:?}");
        assert!(!debug.contains("my-api-key-12345"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn secret_string_expose_returns_value() {
        let s = SecretString::from("hello");
        assert_eq!(s.expose_secret(), "hello");
    }

    #[test]
    fn secret_string_len_and_is_empty() {
        let empty = SecretString::from("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let nonempty = SecretString::from("abc");
        assert!(!nonempty.is_empty());
        assert_eq!(nonempty.len(), 3);
    }

    #[test]
    fn secret_bytes_ct_eq_equal() {
        let a = SecretBytes::from(vec![1u8, 2, 3]);
        let b = SecretBytes::from(vec![1u8, 2, 3]);
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn secret_bytes_ct_eq_different_value() {
        let a = SecretBytes::from(vec![1u8, 2, 3]);
        let b = SecretBytes::from(vec![1u8, 2, 4]);
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn secret_bytes_ct_eq_different_length() {
        let a = SecretBytes::from(vec![1u8, 2, 3]);
        let b = SecretBytes::from(vec![1u8, 2]);
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn secret_bytes_debug_does_not_leak() {
        let b = SecretBytes::from(vec![0xFFu8, 0xAB]);
        let debug = format!("{b:?}");
        assert!(!debug.contains("ff"));
        assert!(!debug.contains("ab"));
        assert!(debug.contains("REDACTED"));
    }
}
