//! Bundle capability strings → a validated capability set.
//!
//! The sandbox drops **all** capabilities and re-grants only this set. The
//! default (an empty `[sandbox] capabilities` list) is therefore "no
//! capabilities at all" — the strongest posture. An unrecognized name is a
//! hard refusal ([`SandboxError::UnknownCapability`]), never silently
//! ignored: a typo must not quietly grant nothing *or* mask intent.

use std::collections::BTreeSet;

use caps::Capability;

use crate::SandboxError;

/// A validated set of capabilities to retain inside the sandbox.
///
/// Stored as the canonical `CAP_*` names in a sorted set so the resolved set
/// is deterministic (stable audit rendering, dedup for free).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    names: BTreeSet<String>,
}

impl CapabilitySet {
    /// Resolve and validate bundle-declared capability strings.
    ///
    /// Names are accepted in informal form (`net_bind_service`,
    /// `CAP_NET_BIND_SERVICE`, …) and normalized; each must resolve to a
    /// real Linux capability.
    ///
    /// # Errors
    /// [`SandboxError::UnknownCapability`] for the first name that is not a
    /// recognized capability. Fail-closed: one bad name rejects the bundle.
    pub fn resolve<I, S>(declared: I) -> Result<Self, SandboxError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut names = BTreeSet::new();
        for raw in declared {
            let raw = raw.as_ref();
            let canonical = caps::to_canonical(raw);
            // `to_canonical` performs no validity check; `from_str` does.
            canonical
                .parse::<Capability>()
                .map_err(|_| SandboxError::UnknownCapability(raw.to_owned()))?;
            names.insert(canonical);
        }
        Ok(Self { names })
    }

    /// True if no capabilities are retained (the default, safest case).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The resolved capabilities as typed values, for the applier to keep
    /// while every other capability is dropped.
    #[must_use]
    pub fn capabilities(&self) -> Vec<Capability> {
        self.names
            .iter()
            // Infallible: every stored name was validated in `resolve`.
            .filter_map(|n| n.parse::<Capability>().ok())
            .collect()
    }

    /// The canonical capability names (sorted), for audit/diagnostics.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.names.iter().map(String::as_str).collect()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::CapabilitySet;
    use crate::SandboxError;
    use caps::Capability;

    #[test]
    fn empty_is_the_default_and_grants_nothing() {
        let set = CapabilitySet::default();
        assert!(set.is_empty());
        assert!(set.capabilities().is_empty());

        let resolved = CapabilitySet::resolve(Vec::<String>::new())
            .expect("empty list resolves");
        assert!(resolved.is_empty());
    }

    #[test]
    fn accepts_informal_and_canonical_names() {
        let set = CapabilitySet::resolve(["net_bind_service", "CAP_KILL"])
            .expect("known capabilities resolve");
        let caps = set.capabilities();
        assert!(caps.contains(&Capability::CAP_NET_BIND_SERVICE));
        assert!(caps.contains(&Capability::CAP_KILL));
        assert_eq!(set.names(), vec!["CAP_KILL", "CAP_NET_BIND_SERVICE"]);
    }

    #[test]
    fn unknown_capability_is_rejected_fail_closed() {
        let err = CapabilitySet::resolve(["CAP_DOES_NOT_EXIST"]).unwrap_err();
        assert_eq!(
            err,
            SandboxError::UnknownCapability("CAP_DOES_NOT_EXIST".to_owned())
        );
        // A single bad name rejects the whole set, even mixed with valid ones.
        assert!(matches!(
            CapabilitySet::resolve(["CAP_KILL", "bogus"]),
            Err(SandboxError::UnknownCapability(_))
        ));
    }

    #[test]
    fn duplicates_collapse_deterministically() {
        let set = CapabilitySet::resolve(["CAP_KILL", "kill", "CAP_KILL"])
            .expect("resolves");
        assert_eq!(set.names(), vec!["CAP_KILL"]);
        assert_eq!(set.capabilities(), vec![Capability::CAP_KILL]);
    }
}
