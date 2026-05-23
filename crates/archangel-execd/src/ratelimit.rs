//! Blast-rate limiting (threat-model layer #12).
//!
//! The executor is the single mutation point and processes actions serially,
//! which makes it the natural place to enforce a **host-wide** ceiling on how
//! fast actions can run. Because this lives in trust tier T2, the cap holds
//! even if the daemon (T3) is compromised: a successful injection or RCE
//! cannot drive the system faster than these limits, no matter how many
//! sessions it forges. That is the containment #12 buys — it bounds the blast
//! *rate*, not whether an individual action is allowed.
//!
//! Three independent sliding windows are checked, every one fail-closed:
//!
//! - total actions per minute,
//! - mutating (`read_only = false`) actions per minute,
//! - `risk = "critical"` actions per hour.
//!
//! An action is admitted only if **all** applicable windows have room; on
//! admission it is recorded in each applicable window. A configured limit of
//! `0` therefore admits nothing (fail-closed), never "unlimited".
//!
//! State is in-memory and per-process, like the replay guard — a restart
//! starts with empty windows, which is safe (it can only *under*-count toward
//! a ceiling right after boot, never grant extra headroom mid-attack).

// Window math reads most clearly in seconds (60s minute, 3600s hour, and the
// test offsets); the larger-unit constructors clippy prefers are unstable.
#![allow(clippy::duration_suboptimal_units)]

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// Configured blast-rate ceilings (from `[rate_limits]`).
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// Max actions of any kind per minute.
    pub actions_per_minute: u32,
    /// Max mutating actions per minute.
    pub mutating_actions_per_minute: u32,
    /// Max critical-risk actions per hour.
    pub critical_actions_per_hour: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            actions_per_minute: 20,
            mutating_actions_per_minute: 5,
            critical_actions_per_hour: 2,
        }
    }
}

/// Classification of the action being admitted; selects which ceilings apply.
#[derive(Debug, Clone, Copy)]
pub struct ActionClass {
    /// The bundle is not `read_only`.
    pub mutating: bool,
    /// The bundle's declared risk is `critical`.
    pub critical: bool,
}

/// Which ceiling shed the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateRejection {
    /// The total actions-per-minute ceiling was hit.
    TotalPerMinute,
    /// The mutating actions-per-minute ceiling was hit.
    MutatingPerMinute,
    /// The critical actions-per-hour ceiling was hit.
    CriticalPerHour,
}

/// A single sliding-window counter: at most `max` admissions within `horizon`.
#[derive(Debug)]
struct Window {
    horizon: Duration,
    max: usize,
    hits: VecDeque<Instant>,
}

impl Window {
    fn new(horizon: Duration, max: u32) -> Self {
        Self {
            horizon,
            max: usize::try_from(max).unwrap_or(usize::MAX),
            hits: VecDeque::new(),
        }
    }

    /// Drop admissions that have aged out of the window relative to `now`.
    fn prune(&mut self, now: Instant) {
        while let Some(&front) = self.hits.front() {
            if now.saturating_duration_since(front) >= self.horizon {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    /// True if admitting now would exceed `max` (also prunes first). `max == 0`
    /// always reports full (fail-closed: nothing is admissible).
    fn is_full(&mut self, now: Instant) -> bool {
        self.prune(now);
        self.hits.len() >= self.max
    }

    fn record(&mut self, now: Instant) {
        self.hits.push_back(now);
    }
}

/// The host-wide blast-rate limiter (#12).
#[derive(Debug)]
pub struct RateLimiter {
    total: Window,
    mutating: Window,
    critical: Window,
}

impl RateLimiter {
    /// Build a limiter from configured ceilings.
    #[must_use]
    pub fn new(limits: RateLimits) -> Self {
        Self {
            total: Window::new(MINUTE, limits.actions_per_minute),
            mutating: Window::new(MINUTE, limits.mutating_actions_per_minute),
            critical: Window::new(HOUR, limits.critical_actions_per_hour),
        }
    }

    /// Try to admit one action at time `now`. Checks every applicable window
    /// *before* recording in any, so a rejection consumes no budget. The
    /// first exceeded ceiling (total → mutating → critical) is reported.
    ///
    /// # Errors
    /// [`RateRejection`] naming the ceiling that is full.
    pub fn try_admit(&mut self, now: Instant, class: ActionClass) -> Result<(), RateRejection> {
        if self.total.is_full(now) {
            return Err(RateRejection::TotalPerMinute);
        }
        if class.mutating && self.mutating.is_full(now) {
            return Err(RateRejection::MutatingPerMinute);
        }
        if class.critical && self.critical.is_full(now) {
            return Err(RateRejection::CriticalPerHour);
        }
        self.total.record(now);
        if class.mutating {
            self.mutating.record(now);
        }
        if class.critical {
            self.critical.record(now);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{ActionClass, RateLimiter, RateLimits, RateRejection};
    use std::time::{Duration, Instant};

    const READ: ActionClass = ActionClass {
        mutating: false,
        critical: false,
    };
    const MUTATE: ActionClass = ActionClass {
        mutating: true,
        critical: false,
    };
    const CRIT: ActionClass = ActionClass {
        mutating: true,
        critical: true,
    };

    fn limits(total: u32, mutating: u32, critical: u32) -> RateLimits {
        RateLimits {
            actions_per_minute: total,
            mutating_actions_per_minute: mutating,
            critical_actions_per_hour: critical,
        }
    }

    #[test]
    fn admits_up_to_total_then_sheds() {
        let mut rl = RateLimiter::new(limits(3, 10, 10));
        let t = Instant::now();
        for _ in 0..3 {
            assert!(rl.try_admit(t, READ).is_ok());
        }
        assert_eq!(rl.try_admit(t, READ), Err(RateRejection::TotalPerMinute));
    }

    #[test]
    fn window_slides_after_horizon() {
        let mut rl = RateLimiter::new(limits(2, 10, 10));
        let t = Instant::now();
        assert!(rl.try_admit(t, READ).is_ok());
        assert!(rl.try_admit(t, READ).is_ok());
        assert!(rl.try_admit(t, READ).is_err());
        // 61s later the first two have aged out.
        let later = t + Duration::from_secs(61);
        assert!(rl.try_admit(later, READ).is_ok());
        assert!(rl.try_admit(later, READ).is_ok());
        assert!(rl.try_admit(later, READ).is_err());
    }

    #[test]
    fn mutating_ceiling_is_independent_of_total() {
        // Plenty of total budget, but only 1 mutating per minute.
        let mut rl = RateLimiter::new(limits(100, 1, 10));
        let t = Instant::now();
        assert!(rl.try_admit(t, MUTATE).is_ok());
        assert_eq!(
            rl.try_admit(t, MUTATE),
            Err(RateRejection::MutatingPerMinute)
        );
        // A read-only action still gets through (different ceiling).
        assert!(rl.try_admit(t, READ).is_ok());
    }

    #[test]
    fn critical_uses_the_hour_window() {
        let mut rl = RateLimiter::new(limits(100, 100, 1));
        let t = Instant::now();
        assert!(rl.try_admit(t, CRIT).is_ok());
        assert_eq!(rl.try_admit(t, CRIT), Err(RateRejection::CriticalPerHour));
        // Still blocked 10 minutes later (hour window).
        assert!(rl.try_admit(t + Duration::from_secs(600), CRIT).is_err());
        // Admissible again after the hour.
        assert!(rl.try_admit(t + Duration::from_secs(3601), CRIT).is_ok());
    }

    #[test]
    fn rejection_consumes_no_budget() {
        // total=1, mutating=0: a mutating action is shed by the mutating
        // ceiling and must NOT have consumed the (still-empty) total budget.
        let mut rl = RateLimiter::new(limits(1, 0, 10));
        let t = Instant::now();
        assert_eq!(
            rl.try_admit(t, MUTATE),
            Err(RateRejection::MutatingPerMinute)
        );
        // The total window still has its single slot free.
        assert!(rl.try_admit(t, READ).is_ok());
    }

    #[test]
    fn zero_limit_is_fail_closed() {
        let mut rl = RateLimiter::new(limits(0, 5, 5));
        assert_eq!(
            rl.try_admit(Instant::now(), READ),
            Err(RateRejection::TotalPerMinute)
        );
    }
}
