//! Replay / reorder protection (architecture §4.2).
//!
//! Every request carries a per-session monotonic `seq` and a random
//! `nonce`. The executor accepts a request only if its `seq` is strictly
//! greater than the highest `seq` already accepted for that session, and
//! the `nonce` has not been seen recently. This defeats:
//!
//! - replay of a previously-valid (validly-signed) request,
//! - reordering of in-flight requests,
//! - duplicate delivery.
//!
//! State is in-memory and per-process. The session key rotates on every
//! `archangeld` restart (architecture §4.2), so a fresh process starting
//! with empty state cannot be tricked with requests signed under an old
//! session key — those fail signature verification first.

use std::collections::{HashMap, HashSet, VecDeque};

use archangel_core::SessionId;

/// Why a request was refused by the replay guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejection {
    /// `seq` was not strictly greater than the last accepted one.
    NonMonotonicSeq,
    /// `nonce` was seen within the dedupe window.
    DuplicateNonce,
}

/// Bounded per-session replay state.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    last_seq: HashMap<SessionId, u64>,
    seen_nonces: HashSet<[u8; 16]>,
    nonce_order: VecDeque<[u8; 16]>,
}

/// How many recent nonces to remember (defense in depth alongside `seq`;
/// `seq` monotonicity is the primary control, so this need not be huge).
const NONCE_WINDOW: usize = 4096;

impl ReplayGuard {
    /// A fresh guard with no history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check and, on success, record a request. Returns `Ok(())` if the
    /// request is fresh; otherwise the reason it is a replay.
    ///
    /// This both checks and commits: a rejected request leaves state
    /// unchanged, so a flood of replays cannot poison the window.
    pub fn admit(
        &mut self,
        session: SessionId,
        seq: u64,
        nonce: [u8; 16],
    ) -> Result<(), ReplayRejection> {
        if let Some(&last) = self.last_seq.get(&session) {
            if seq <= last {
                return Err(ReplayRejection::NonMonotonicSeq);
            }
        }
        if self.seen_nonces.contains(&nonce) {
            return Err(ReplayRejection::DuplicateNonce);
        }

        // Commit.
        self.last_seq.insert(session, seq);
        self.seen_nonces.insert(nonce);
        self.nonce_order.push_back(nonce);
        if self.nonce_order.len() > NONCE_WINDOW {
            if let Some(evicted) = self.nonce_order.pop_front() {
                self.seen_nonces.remove(&evicted);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use archangel_core::SessionId;

    use super::{ReplayGuard, ReplayRejection};

    #[test]
    fn first_request_is_admitted() {
        let mut g = ReplayGuard::new();
        assert!(g.admit(SessionId::new(), 1, [1u8; 16]).is_ok());
    }

    #[test]
    fn strictly_increasing_seq_is_required() {
        let mut g = ReplayGuard::new();
        let s = SessionId::new();
        assert!(g.admit(s, 5, [1u8; 16]).is_ok());
        assert_eq!(
            g.admit(s, 5, [2u8; 16]),
            Err(ReplayRejection::NonMonotonicSeq),
            "same seq is a replay"
        );
        assert_eq!(
            g.admit(s, 4, [3u8; 16]),
            Err(ReplayRejection::NonMonotonicSeq),
            "lower seq is a replay"
        );
        assert!(g.admit(s, 6, [4u8; 16]).is_ok(), "higher seq advances");
    }

    #[test]
    fn duplicate_nonce_is_rejected_even_with_higher_seq() {
        let mut g = ReplayGuard::new();
        let s = SessionId::new();
        let n = [9u8; 16];
        assert!(g.admit(s, 1, n).is_ok());
        assert_eq!(
            g.admit(s, 2, n),
            Err(ReplayRejection::DuplicateNonce),
            "a reused nonce is refused regardless of seq"
        );
    }

    #[test]
    fn sessions_are_independent() {
        let mut g = ReplayGuard::new();
        let a = SessionId::new();
        let b = SessionId::new();
        assert!(g.admit(a, 10, [1u8; 16]).is_ok());
        // A different session starting at a low seq is fine.
        assert!(g.admit(b, 1, [2u8; 16]).is_ok());
    }

    #[test]
    fn rejected_request_does_not_advance_state() {
        let mut g = ReplayGuard::new();
        let s = SessionId::new();
        assert!(g.admit(s, 5, [1u8; 16]).is_ok());
        let _ = g.admit(s, 3, [2u8; 16]); // rejected
                                          // seq state is still 5, so 6 must work and 5 must still fail.
        assert!(g.admit(s, 6, [3u8; 16]).is_ok());
    }
}
