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

use archangel_core::{OperationMode, RiskLevel};

/// The outcome of evaluating an action against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Permitted to run now: nothing denied, allowlisted, and no human
    /// approval is required for this mode/risk.
    Allow,
    /// Not denied and allowlisted, but a human must approve it first
    /// (layer #13). The executor MUST NOT run it until a valid operator
    /// approval is presented.
    RequireApproval {
        /// Why approval is required (mode/risk), for the operator + audit.
        reason: String,
        /// `true` if two independent operator signatures are required
        /// (layer #14 — `risk = "critical"`).
        two_person: bool,
    },
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
    /// `true` only for [`PolicyDecision::Allow`] — i.e. safe to run *now*
    /// with no further gating. `RequireApproval` is deliberately NOT
    /// "allowed": callers must route it through the approval flow.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// `true` if the action is permissible but gated on human approval.
    #[must_use]
    pub const fn needs_approval(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
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
    /// Risk the **verified** bundle declares (drives approval / two-person).
    pub risk: RiskLevel,
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
        if !self
            .allowlist
            .is_allowed(request.profile, request.exec, request.mode)
        {
            return PolicyDecision::NotAllowed {
                reason: format!(
                    "exec {:?} is not allowlisted for profile {:?} in {:?} mode",
                    request.exec, request.profile, request.mode
                ),
            };
        }

        // 4. Approval gating (layers #13/#14). Allowlisted + not denied,
        //    but a human may still need to approve before it runs:
        //    - interactive mode: every action is approved by the operator;
        //    - critical risk: two-person rule, in ANY mode (defense in
        //      depth — even autonomous cannot self-authorize a critical).
        let two_person = request.risk.requires_two_person_rule();
        if request.mode.requires_human_approval() {
            PolicyDecision::RequireApproval {
                reason: format!(
                    "interactive mode requires operator approval (risk={:?})",
                    request.risk
                ),
                two_person,
            }
        } else if two_person {
            PolicyDecision::RequireApproval {
                reason: "critical risk requires the two-person rule".to_owned(),
                two_person: true,
            }
        } else {
            PolicyDecision::Allow
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
    use archangel_core::{OperationMode, RiskLevel};

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

[[profile]]
name = "ops"
mode = "interactive"
allowed_exec = ["restart-svc", "danger-op"]

[[profile]]
name = "auto"
mode = "autonomous"
allowed_exec = ["rotate-logs", "wipe-disk"]
"#,
        )
        .expect("valid allowlist");
        PolicyEngine::new(al)
    }

    fn req<'a>(
        profile: &'a str,
        mode: OperationMode,
        exec: &'a str,
        risk: RiskLevel,
        commands: &'a [&'a str],
        paths: &'a [PathIntent<'a>],
    ) -> PolicyRequest<'a> {
        PolicyRequest {
            profile,
            mode,
            exec,
            risk,
            commands,
            paths,
        }
    }

    #[test]
    fn read_only_benign_action_runs_without_approval() {
        let r = req(
            "default",
            OperationMode::ReadOnly,
            "read-logs",
            RiskLevel::Low,
            &["journalctl -u nginx --no-pager -n 100"],
            &[PathIntent {
                path: "/var/log/nginx/access.log",
                access: PathAccess::Read,
            }],
        );
        assert_eq!(engine().evaluate(&r), PolicyDecision::Allow);
    }

    #[test]
    fn denylisted_command_overrides_everything() {
        let r = req(
            "default",
            OperationMode::ReadOnly,
            "read-logs",
            RiskLevel::Low,
            &["rm -rf /"],
            &[],
        );
        assert!(matches!(engine().evaluate(&r), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn denylisted_path_overrides_allowlist() {
        let r = req(
            "default",
            OperationMode::ReadOnly,
            "read-logs",
            RiskLevel::Low,
            &[],
            &[PathIntent {
                path: "/etc/archangel/../archangel/keys/audit.key",
                access: PathAccess::Write,
            }],
        );
        assert!(matches!(engine().evaluate(&r), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn not_allowlisted_is_refused() {
        let r = req(
            "default",
            OperationMode::ReadOnly,
            "totally-unknown-exec",
            RiskLevel::Low,
            &[],
            &[],
        );
        assert!(matches!(
            engine().evaluate(&r),
            PolicyDecision::NotAllowed { .. }
        ));
    }

    #[test]
    fn interactive_mode_always_requires_approval() {
        // Layer #13: every action in interactive mode is gated on a human,
        // and is NOT "allowed" (must not auto-execute).
        let r = req(
            "ops",
            OperationMode::Interactive,
            "restart-svc",
            RiskLevel::Medium,
            &["systemctl restart nginx"],
            &[],
        );
        let d = engine().evaluate(&r);
        assert!(matches!(
            d,
            PolicyDecision::RequireApproval { two_person: false, .. }
        ));
        assert!(!d.is_allowed(), "approval-gated must never be is_allowed()");
        assert!(d.needs_approval());
    }

    #[test]
    fn interactive_critical_requires_two_person() {
        let r = req(
            "ops",
            OperationMode::Interactive,
            "danger-op",
            RiskLevel::Critical,
            &[],
            &[],
        );
        assert!(matches!(
            engine().evaluate(&r),
            PolicyDecision::RequireApproval { two_person: true, .. }
        ));
    }

    #[test]
    fn autonomous_low_risk_runs_unattended() {
        let r = req(
            "auto",
            OperationMode::Autonomous,
            "rotate-logs",
            RiskLevel::Low,
            &[],
            &[],
        );
        assert_eq!(engine().evaluate(&r), PolicyDecision::Allow);
    }

    #[test]
    fn autonomous_cannot_self_authorize_a_critical_action() {
        // Layer #14: even autonomous mode needs the two-person rule for a
        // critical action — it cannot rubber-stamp itself.
        let r = req(
            "auto",
            OperationMode::Autonomous,
            "wipe-disk",
            RiskLevel::Critical,
            &[],
            &[],
        );
        assert!(matches!(
            engine().evaluate(&r),
            PolicyDecision::RequireApproval { two_person: true, .. }
        ));
    }

    #[test]
    fn wrong_mode_for_profile_is_refused() {
        // "default" is a read_only profile; asking for it in autonomous
        // mode must not be allowed.
        let r = req(
            "default",
            OperationMode::Autonomous,
            "read-logs",
            RiskLevel::Low,
            &[],
            &[],
        );
        assert!(!engine().evaluate(&r).is_allowed());
    }
}
