//! `archangelctl` library surface.
//!
//! The operator CLI is never privileged. v0.1 ships the security-critical,
//! self-contained pieces:
//!
//! - [`render`] — the secure terminal renderer. Untrusted content (model
//!   output, command output, audit payloads) is sanitized so it can never
//!   emit terminal escapes and spoof archangelctl's own chrome. This is a
//!   security control, not cosmetics.
//! - [`keys`] — operator key generation/loading with no-clobber, `0600`.
//! - [`audit_view`] — verify an audit log against a pinned key and render
//!   it safely.
//!
//! The interactive session REPL and `policy reload` need the daemon's
//! control socket (boundary A) and land with the `archangeld` runtime
//! milestone; the CLI reports that honestly rather than faking a protocol.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
/// Verify and display an audit log.
pub mod audit_view;
/// Signed control-plane client (boundary A).
pub mod client;
/// Host readiness preflight (`archangel-doctor`).
pub mod doctor;
/// Operator key material.
pub mod keys;
/// Secure terminal rendering.
pub mod render;
/// Safe rendering of daemon control responses.
pub mod view;

pub use audit_view::verify_and_render;
pub use client::CtlClient;
pub use doctor::{diagnose, Report};
pub use error::CtlError;
pub use keys::{init_operator_key, load_operator_key};
pub use render::{sanitize_untrusted, Block, Palette};
pub use view::render_response;
