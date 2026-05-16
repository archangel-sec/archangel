//! Policy engine for archangel.
//!
//! Two layers live here:
//!
//! - **#8 — the immutable denylist** ([`denylist`]): compiled into the
//!   binary, authoritative, final. A denylist match can never be overridden.
//! - **#9 — the allowlist** ([`allowlist`]): per-profile list of permitted
//!   `.exec` bundles. v0.1 is a simple unsigned loader; signed bundles and a
//!   WASM policy stage come in v0.3.
//!
//! Evaluation order is **deny-first and fail-closed**:
//!
//! 1. every command the action would run is checked against the denylist;
//! 2. every path the action would touch is checked against the denylist;
//! 3. only if nothing is denied, the allowlist must *explicitly* permit the
//!    `.exec` bundle for the active profile and mode;
//! 4. anything not explicitly allowed is refused.
//!
//! A denied or unprovable input never becomes "allowed". This module makes
//! the *decision*; enforcement (sandboxing, re-validation) is the executor's
//! job — see the threat model.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Policy subsystem error types.
pub mod error;
/// Immutable, compiled-in denylist (layer #8).
pub mod denylist;
/// Per-profile allowlist loader (layer #9, v0.1 subset).
pub mod allowlist;
/// Lexical path normalization (denylist evasion resistance).
pub mod pathnorm;

pub use allowlist::{Allowlist, ProfileAllow};
pub use denylist::{DenyCategory, DenyMatch, Denylist, PathAccess};
pub use error::PolicyError;

use archangel_core::OperationMode;

/// The outcome of evaluating an action against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Permitted: nothing denied, and the allowlist explicitly permits it.
    Allow,
    /// Forbidden by the immutable denylist. This is final.
    Deny {
        /// Category of the denylist rule that fired.
        category: DenyCategory,
        /// Stable id of the rule.
        rule_id: &'static str,
        /// Human-readable reason (suitable for the audit log).
        reason: String,
    },
    /// Not denied, but not explicitly allowed either. Fail-closed default.
    NotAllowed {
        /// Why it was not allowed.
        reason: String,
    },
}

impl PolicyDecision {
    /// `true` only for [`PolicyDecision::Allow`].
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// A single path the action intends to touch.
#[derive(Debug, Clone, Copy)]
pub struct PathIntent<'a> {
    /// The path (will be lexically normalized before matching).
    pub path: &'a str,
    /// The access requested.
    pub access: PathAccess,
}

/// Everything policy needs to know about a proposed action.
#[derive(Debug, Clone, Copy)]
pub struct PolicyRequest<'a> {
    /// Active profile name.
    pub profile: &'a str,
    /// Active operating mode.
    pub mode: OperationMode,
    /// The `.exec` bundle name the action resolved to.
    pub exec: &'a str,
    /// Commands the bundle would execute (denylist backstop input).
    pub commands: &'a [&'a str],
    /// Paths the bundle would touch.
    pub paths: &'a [PathIntent<'a>],
}

/// The combined policy engine: the immutable denylist plus a loaded
/// allowlist.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    allowlist: Allowlist,
}

impl PolicyEngine {
    /// Build an engine around an already-loaded allowlist.
    #[must_use]
    pub const fn new(allowlist: Allowlist) -> Self {
        Self { allowlist }
    }

    /// The allowlist in force.
    #[must_use]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// Evaluate a request. Deny-first, fail-closed.
    ///
    /// On any error normalizing a path, the result is [`PolicyDecision::Deny`]
    /// — never an allow — because an input we cannot reason about safely is
    /// treated as hostile.
    #[must_use]
    pub fn evaluate(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        // 1. Denylist: commands.
        for command in request.commands {
            if let Some(m) = Denylist::check_command(command) {
                return deny_from(&m);
            }
        }

        // 2. Denylist: paths.
        for intent in request.paths {
            match Denylist::check_path(intent.path, intent.access) {
                Ok(Some(m)) => return deny_from(&m),
                Ok(None) => {}
                Err(e) => {
                    // Unreachable in practice (check_path maps BadPath to a
                    // synthetic deny), but if a new error variant ever
                    // appears, fail closed rather than fall through.
                    return PolicyDecision::Deny {
                        category: DenyCategory::SelfProtection,
                        rule_id: "path-evaluation-error",
                        reason: format!("path could not be evaluated: {e}"),
                    };
                }
            }
        }

        // 3. Allowlist must explicitly permit this exec for profile+mode.
        if self
            .allowlist
            .is_allowed(request.profile, request.exec, request.mode)
        {
            PolicyDecision::Allow
        } else {
            PolicyDecision::NotAllowed {
                reason: format!(
                    "exec {:?} is not allowlisted for profile {:?} in {:?} mode",
                    request.exec, request.profile, request.mode
                ),
            }
        }
    }
}

fn deny_from(m: &DenyMatch) -> PolicyDecision {
    PolicyDecision::Deny {
        category: m.category,
        rule_id: m.rule_id,
        reason: format!("{} (matched {:?})", m.description, m.matched),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use archangel_core::OperationMode;

    use super::{
        Allowlist, PathAccess, PathIntent, PolicyDecision, PolicyEngine, PolicyRequest,
    };

    fn engine() -> PolicyEngine {
        let al = Allowlist::from_toml(
            r#"
[[profile]]
name = "default"
mode = "read_only"
allowed_exec = ["read-logs"]
"#,
        )
        .expect("valid allowlist");
        PolicyEngine::new(al)
    }

    #[test]
    fn allowlisted_benign_action_is_allowed() {
        let req = PolicyRequest {
            profile: "default",
            mode: OperationMode::ReadOnly,
            exec: "read-logs",
            commands: &["journalctl -u nginx --no-pager -n 100"],
            paths: &[PathIntent {
                path: "/var/log/nginx/access.log",
                access: PathAccess::Read,
            }],
        };
        assert_eq!(engine().evaluate(&req), PolicyDecision::Allow);
    }

    #[test]
    fn denylisted_command_overrides_everything() {
        // Even an allowlisted exec cannot run a denylisted command.
        let req = PolicyRequest {
            profile: "default",
            mode: OperationMode::ReadOnly,
            exec: "read-logs",
            commands: &["rm -rf /"],
            paths: &[],
        };
        assert!(matches!(
            engine().evaluate(&req),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn denylisted_path_overrides_allowlist() {
        let req = PolicyRequest {
            profile: "default",
            mode: OperationMode::ReadOnly,
            exec: "read-logs",
            commands: &[],
            paths: &[PathIntent {
                path: "/etc/archangel/../archangel/keys/audit.key",
                access: PathAccess::Write,
            }],
        };
        assert!(matches!(
            engine().evaluate(&req),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn not_allowlisted_is_refused_not_allowed() {
        let req = PolicyRequest {
            profile: "default",
            mode: OperationMode::ReadOnly,
            exec: "totally-unknown-exec",
            commands: &[],
            paths: &[],
        };
        assert!(matches!(
            engine().evaluate(&req),
            PolicyDecision::NotAllowed { .. }
        ));
    }

    #[test]
    fn wrong_mode_is_refused() {
        let req = PolicyRequest {
            profile: "default",
            mode: OperationMode::Autonomous,
            exec: "read-logs",
            commands: &[],
            paths: &[],
        };
        assert!(!engine().evaluate(&req).is_allowed());
    }
}
