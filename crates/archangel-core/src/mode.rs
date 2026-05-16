//! Operation modes and risk classifications.

use serde::{Deserialize, Serialize};

/// The three modes of operation supported by archangel.
///
/// The mode is chosen once at session start and cannot be escalated during
/// an active session. Downgrading also requires re-authentication, preventing
/// a compromised LLM conversation from silently acquiring more trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    /// The agent may only invoke actions marked `read_only = true` in their
    /// `.exec` bundle. No mutation of system state is possible in this mode.
    ReadOnly,

    /// Every proposed action is presented to a human operator for approval
    /// before execution. The operator may approve, reject, or modify the action.
    Interactive,

    /// Actions proceed without per-action human approval, subject only to
    /// the compiled denylist, the active signed allowlist, and rate limits.
    Autonomous,
}

/// Risk classification of a proposed action.
///
/// Variants are ordered: `Low < Medium < High < Critical`. The executor
/// enforces minimum approval requirements based on this level — higher
/// risk requires stronger authorization regardless of the active mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Read-only inspection with no persistent side effects.
    Low,

    /// Modifies runtime state; easily reversible (e.g., restart a service).
    Medium,

    /// Modifies persistent state. A filesystem snapshot is taken before
    /// execution when the host supports it (BTRFS / LVM thin).
    High,

    /// Potentially irreversible or destructive. Requires the two-person rule
    /// in [`OperationMode::Autonomous`] and explicit diff-level confirmation
    /// in [`OperationMode::Interactive`].
    Critical,
}

impl OperationMode {
    /// Returns `true` if this mode permits mutation of system state.
    #[must_use]
    pub const fn allows_mutation(self) -> bool {
        matches!(self, Self::Interactive | Self::Autonomous)
    }

    /// Returns `true` if every proposed action requires explicit human
    /// approval before the executor will run it.
    #[must_use]
    pub const fn requires_human_approval(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

impl RiskLevel {
    /// Returns `true` if two independent operator signatures are required
    /// before the executor will run this action in autonomous mode.
    #[must_use]
    pub const fn requires_two_person_rule(self) -> bool {
        matches!(self, Self::Critical)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{OperationMode, RiskLevel};

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn read_only_does_not_allow_mutation() {
        assert!(!OperationMode::ReadOnly.allows_mutation());
    }

    #[test]
    fn interactive_and_autonomous_allow_mutation() {
        assert!(OperationMode::Interactive.allows_mutation());
        assert!(OperationMode::Autonomous.allows_mutation());
    }

    #[test]
    fn only_interactive_requires_human_approval() {
        assert!(OperationMode::Interactive.requires_human_approval());
        assert!(!OperationMode::Autonomous.requires_human_approval());
        assert!(!OperationMode::ReadOnly.requires_human_approval());
    }

    #[test]
    fn only_critical_requires_two_person_rule() {
        assert!(RiskLevel::Critical.requires_two_person_rule());
        assert!(!RiskLevel::High.requires_two_person_rule());
    }

    #[test]
    fn mode_serde_round_trip() -> Result<(), serde_json::Error> {
        for mode in [
            OperationMode::ReadOnly,
            OperationMode::Interactive,
            OperationMode::Autonomous,
        ] {
            let json = serde_json::to_string(&mode)?;
            let parsed: OperationMode = serde_json::from_str(&json)?;
            assert_eq!(mode, parsed);
        }
        Ok(())
    }

    #[test]
    fn risk_serde_round_trip() -> Result<(), serde_json::Error> {
        for level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&level)?;
            let parsed: RiskLevel = serde_json::from_str(&json)?;
            assert_eq!(level, parsed);
        }
        Ok(())
    }
}
