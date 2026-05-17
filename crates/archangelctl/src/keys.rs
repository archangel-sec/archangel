//! Operator key material.
//!
//! The operator's Ed25519 key authenticates control-plane requests to the
//! daemon (boundary A). `archangelctl` itself is never privileged; this key
//! is the operator's identity, so it is treated as **CRITICAL** material:
//!
//! - generated from the OS CSPRNG,
//! - written with `O_CREAT | O_EXCL` and mode `0600` — an existing key is
//!   **never** silently overwritten (clobbering a key is a way to lose
//!   identity or be socially-engineered into regenerating one),
//! - the secret is held in a zeroizing buffer off-disk and the in-memory
//!   `SigningKey` zeroizes on drop (ed25519-dalek `zeroize`).

use std::{
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use ed25519_dalek::SigningKey;

use archangel_core::SecretString;

use crate::error::CtlError;

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>, CtlError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(CtlError::Key("odd-length hex".to_owned()));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let hi = nibble(*p.first().ok_or_else(|| CtlError::Key("hex".into()))?)?;
            let lo = nibble(*p.get(1).ok_or_else(|| CtlError::Key("hex".into()))?)?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn nibble(b: u8) -> Result<u8, CtlError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(CtlError::Key("invalid hex char".to_owned())),
    }
}

/// Generate a fresh operator keypair and persist it.
///
/// Returns the public key hex. Fails (without writing anything) if either
/// path already exists.
pub fn init_operator_key(
    secret_path: &Path,
    public_path: &Path,
) -> Result<String, CtlError> {
    if secret_path.exists() || public_path.exists() {
        return Err(CtlError::Key(format!(
            "refusing to overwrite existing key material at {} / {}",
            secret_path.display(),
            public_path.display()
        )));
    }

    let mut csprng = rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let public_hex = encode_hex(signing.verifying_key().as_bytes());
    let secret_hex = SecretString::new(encode_hex(&signing.to_bytes()));

    // O_EXCL: atomic "create only if absent"; mode 0600 from the start.
    let mut sk_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(secret_path)
        .map_err(|e| CtlError::Key(format!("create secret file: {e}")))?;
    sk_file
        .write_all(secret_hex.expose_secret().as_bytes())
        .map_err(|e| CtlError::Key(format!("write secret: {e}")))?;
    sk_file
        .write_all(b"\n")
        .map_err(|e| CtlError::Key(format!("write secret: {e}")))?;

    let mut pk_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(public_path)
        .map_err(|e| CtlError::Key(format!("create public file: {e}")))?;
    pk_file
        .write_all(format!("{public_hex}\n").as_bytes())
        .map_err(|e| CtlError::Key(format!("write public: {e}")))?;

    Ok(public_hex)
}

/// Load an operator signing key from a hex secret file.
pub fn load_operator_key(secret_path: &Path) -> Result<SigningKey, CtlError> {
    let text = std::fs::read_to_string(secret_path)
        .map_err(|e| CtlError::Key(format!("read secret: {e}")))?;
    let bytes = decode_hex(&text)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CtlError::Key("secret must be 32 bytes".to_owned()))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{init_operator_key, load_operator_key};

    fn tmp() -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "archangelctl-keys-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn init_then_load_round_trips() {
        let d = tmp();
        let sk = d.join("op.key");
        let pk = d.join("op.pub");
        let pub_hex = init_operator_key(&sk, &pk).expect("init");
        let loaded = load_operator_key(&sk).expect("load");
        assert_eq!(
            super::encode_hex(loaded.verifying_key().as_bytes()),
            pub_hex
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_to_overwrite_existing_key() {
        let d = tmp();
        let sk = d.join("op.key");
        let pk = d.join("op.pub");
        init_operator_key(&sk, &pk).expect("first init ok");
        let again = init_operator_key(&sk, &pk);
        assert!(again.is_err(), "must not clobber existing key material");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn secret_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmp();
        let sk = d.join("op.key");
        let pk = d.join("op.pub");
        init_operator_key(&sk, &pk).expect("init");
        let mode = std::fs::metadata(&sk).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secret key must be 0600");
        let _ = std::fs::remove_dir_all(&d);
    }
}
