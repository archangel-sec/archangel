//! `.exec` bundle parser and signature verifier (threat model layers #6/#7).
//!
//! A `.exec` bundle is a TOML manifest describing one action: its risk, its
//! argument schema, its declarative sandbox, and its payload. A detached
//! `.exec.sig` carries an Ed25519 signature over the exact manifest bytes,
//! chained to an operator key in the trust set.
//!
//! This crate's single security promise: **nothing leaves here trusted
//! unless a trusted operator key signed it.** That promise is enforced by
//! the type system — see [`VerifiedBundle`], which cannot be constructed
//! except through signature verification, and does not implement
//! `Deserialize`.
//!
//! Pipeline (order is load-bearing):
//!
//! 1. verify detached signature over raw manifest bytes ([`verify`]);
//! 2. parse the now-authenticated TOML ([`manifest`]);
//! 3. confirm the payload SHA-256 matches the signed manifest;
//! 4. later, validate LLM-supplied arguments against the schema ([`args`]).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Argument schema validation (layer #7).
pub mod args;
/// `.exec` format error types.
pub mod error;
mod hex;
/// Typed manifest and parser.
pub mod manifest;
/// Operator trust set.
pub mod trust;
/// Signature verification and the verified-bundle typestate.
pub mod verify;

pub use error::ExecFormatError;
pub use manifest::{
    ArgSpec, ArgType, ExecManifest, HealthCheck, Meta, NetworkPolicy, Payload, PayloadType,
    SandboxSpec,
};
pub use trust::OperatorTrust;
pub use verify::VerifiedBundle;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::{ExecFormatError, OperatorTrust, VerifiedBundle};

    // Kept free of TOML-significant characters so the test fixture string
    // stays simple; the payload content is irrelevant to format tests.
    const SCRIPT: &str = "systemctl restart the-target-service";

    fn payload_sha() -> String {
        let d: [u8; 32] = Sha256::digest(SCRIPT.as_bytes()).into();
        super::hex::encode(&d)
    }

    fn manifest_toml() -> String {
        format!(
            r#"
[meta]
name = "restart-service"
version = "1.0.0"
risk = "medium"
read_only = false
mutates_persistent_state = false
requires_network = false

[args]
service = {{ type = "string", regex = "[a-z0-9.-]+\\.service", required = true }}

[sandbox]
syscall_profile = "service-management"
network = "none"
timeout_seconds = 30

[payload]
type = "bash"
sha256 = "{}"
inline = "{}"
"#,
            payload_sha(),
            SCRIPT
        )
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn trust_for(key: &SigningKey) -> OperatorTrust {
        let pub_hex = super::hex::encode(key.verifying_key().as_bytes());
        OperatorTrust::from_str(&format!("{pub_hex}  operator-alice")).expect("trust parses")
    }

    fn sign(text: &str, key: &SigningKey) -> String {
        super::hex::encode(&key.sign(text.as_bytes()).to_bytes())
    }

    #[test]
    fn valid_bundle_verifies_and_parses() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let bundle = VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key))
            .expect("valid bundle must verify");
        assert_eq!(bundle.manifest().meta.name, "restart-service");
        assert!(!bundle.manifest().meta.read_only);
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let mut tampered = toml;
        tampered.push(' '); // one extra byte → signature no longer covers it
        let result = VerifiedBundle::verify_bytes(tampered.as_bytes(), &sig, &trust_for(&key));
        assert!(matches!(result, Err(ExecFormatError::Untrusted)));
    }

    #[test]
    fn foreign_key_is_rejected() {
        let author = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &author);
        let attacker_trust = trust_for(&SigningKey::from_bytes(&[9u8; 32]));
        let result = VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &attacker_trust);
        assert!(matches!(result, Err(ExecFormatError::Untrusted)));
    }

    #[test]
    fn empty_trust_set_rejects_everything() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let nobody = OperatorTrust::default();
        assert!(nobody.is_empty());
        let result = VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &nobody);
        assert!(matches!(result, Err(ExecFormatError::Untrusted)));
    }

    #[test]
    fn payload_hash_mismatch_is_rejected() {
        let key = signing_key();
        // Declare a wrong hash, then sign — signature is valid but the
        // payload does not match the (signed) manifest.
        let toml = manifest_toml().replace(&payload_sha(), &"0".repeat(64));
        let sig = sign(&toml, &key);
        let result = VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key));
        assert!(matches!(
            result,
            Err(ExecFormatError::PayloadHashMismatch { .. })
        ));
    }

    #[test]
    fn unknown_manifest_field_is_rejected() {
        let key = signing_key();
        let toml = format!("{}\n[meta.backdoor]\nenabled = true\n", manifest_toml());
        let sig = sign(&toml, &key);
        let result = VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key));
        assert!(matches!(result, Err(ExecFormatError::BadManifest(_))));
    }

    #[test]
    fn args_required_and_pattern_ok() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let bundle =
            VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key)).expect("verify");
        let mut provided = BTreeMap::new();
        provided.insert("service".to_owned(), "nginx.service".to_owned());
        assert!(bundle.validate_args(&provided).is_ok());
    }

    #[test]
    fn args_missing_required_is_rejected() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let bundle =
            VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key)).expect("verify");
        let provided = BTreeMap::new();
        assert!(matches!(
            bundle.validate_args(&provided),
            Err(ExecFormatError::ArgRejected(_))
        ));
    }

    #[test]
    fn undeclared_argument_is_rejected() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let bundle =
            VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key)).expect("verify");
        let mut provided = BTreeMap::new();
        provided.insert("service".to_owned(), "nginx.service".to_owned());
        provided.insert("extra_injected".to_owned(), "--privileged".to_owned());
        assert!(matches!(
            bundle.validate_args(&provided),
            Err(ExecFormatError::ArgRejected(_))
        ));
    }

    #[test]
    fn anchored_regex_blocks_partial_match_injection() {
        let key = signing_key();
        let toml = manifest_toml();
        let sig = sign(&toml, &key);
        let bundle =
            VerifiedBundle::verify_bytes(toml.as_bytes(), &sig, &trust_for(&key)).expect("verify");
        let mut provided = BTreeMap::new();
        // Starts like a valid service name but appends a command. The
        // schema regex is anchored, so this must be rejected.
        provided.insert("service".to_owned(), "nginx.service; rm -rf /".to_owned());
        assert!(matches!(
            bundle.validate_args(&provided),
            Err(ExecFormatError::ArgRejected(_))
        ));
    }

    #[test]
    fn trust_file_parsing_handles_comments_and_bad_lines() {
        let key = signing_key();
        let good = super::hex::encode(key.verifying_key().as_bytes());
        let text = format!("# operators\n\n{good} alice\n");
        let trust = OperatorTrust::from_str(&text).expect("parses");
        assert_eq!(trust.len(), 1);

        assert!(matches!(
            OperatorTrust::from_str("not-hex-at-all"),
            Err(ExecFormatError::BadTrustFile(_))
        ));
    }

    #[test]
    fn malformed_signature_is_rejected() {
        let key = signing_key();
        let toml = manifest_toml();
        let result = VerifiedBundle::verify_bytes(toml.as_bytes(), "xyz", &trust_for(&key));
        assert!(matches!(result, Err(ExecFormatError::BadSignature(_))));
    }
}
