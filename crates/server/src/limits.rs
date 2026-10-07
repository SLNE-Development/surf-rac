//! In-memory rate limiting and login lockout.
//!
//! State lives in process memory and resets when the server restarts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of tracked keys above which stale entries are pruned.
const PRUNE_THRESHOLD: usize = 10_000;

/// Fixed-window limiter allowing `max` hits per key within each window.
pub struct RateLimiter {
    /// Hits allowed per window.
    max: u32,
    /// Length of a window.
    window: Duration,
    /// Per key: start of the current window and hits counted in it.
    entries: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// Creates a limiter allowing `max` hits per key every `window`.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Counts a hit for `key` at `now` and returns whether it is within the limit.
    pub fn check(&self, key: &str, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() > PRUNE_THRESHOLD {
            let window = self.window;
            entries.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = entries.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.max {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Per-key state of a [`Lockout`].
#[derive(Default)]
struct LockState {
    /// Consecutive failures since the last success or lock.
    failures: u32,
    /// When the current lock ends, if locked.
    locked_until: Option<Instant>,
    /// When the last failure was recorded.
    last_failure: Option<Instant>,
}

/// Locks a key for a fixed time after too many consecutive failures.
pub struct Lockout {
    /// Consecutive failures that trigger a lock.
    max_failures: u32,
    /// How long a lock lasts.
    lock_for: Duration,
    /// State per key.
    entries: Mutex<HashMap<String, LockState>>,
}

impl Lockout {
    /// Creates a lockout that locks for `lock_for` after `max_failures` consecutive failures.
    pub fn new(max_failures: u32, lock_for: Duration) -> Self {
        Self {
            max_failures,
            lock_for,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the remaining lock time of `key` at `now`, or `None` if it is not locked.
    pub fn is_locked(&self, key: &str, now: Instant) -> Option<Duration> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let state = entries.get_mut(key)?;
        match state.locked_until {
            Some(until) if until > now => Some(until - now),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Records a failed attempt for `key` at `now`, locking it once the limit is reached.
    pub fn record_failure(&self, key: &str, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.fail(&mut entries, key, now);
    }

    /// Counts a failure for `key` in the already locked `entries`, pruning stale keys first.
    fn fail(&self, entries: &mut HashMap<String, LockState>, key: &str, now: Instant) {
        if entries.len() > PRUNE_THRESHOLD {
            let lock_for = self.lock_for;
            entries.retain(|_, s| {
                s.locked_until.is_some_and(|u| u > now)
                    || s.last_failure.is_some_and(|t| now.duration_since(t) < lock_for)
            });
        }
        let state = entries.entry(key.to_owned()).or_default();
        if state.locked_until.is_some_and(|u| u <= now) {
            *state = LockState::default();
        }
        state.last_failure = Some(now);
        state.failures += 1;
        if state.failures >= self.max_failures {
            state.failures = 0;
            state.locked_until = Some(now + self.lock_for);
        }
    }

    /// Reserves an attempt for `key` at `now`, counting it as a failure up front.
    ///
    /// Returns the remaining lock time when `key` is locked. The check and the
    /// count happen back to back on every call, so concurrent attempts cannot
    /// exceed the failure limit. A successful attempt must call
    /// [`Lockout::record_success`], which also lifts a lock that this attempt
    /// itself triggered.
    pub fn try_attempt(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = entries.get(key).and_then(|s| s.locked_until)
            && until > now
        {
            return Err(until - now);
        }
        self.fail(&mut entries, key, now);
        Ok(())
    }

    /// Returns the number of tracked keys.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Clears the failure count of `key` after a successful attempt.
    pub fn record_success(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(key);
    }
}

/// All limiters of the server, configured with the fixed production values.
pub struct Limits {
    /// Login attempts per client IP: 10 per minute.
    pub login_ip: RateLimiter,
    /// Registration attempts per client IP: 5 per minute.
    pub register_ip: RateLimiter,
    /// Account lock: 15 minutes after 5 consecutive failed logins.
    pub lockout: Lockout,
}

impl Default for Limits {
    /// Creates the limiters with the production values.
    fn default() -> Self {
        Self {
            login_ip: RateLimiter::new(10, Duration::from_secs(60)),
            register_ip: RateLimiter::new(5, Duration::from_secs(60)),
            lockout: Lockout::new(5, Duration::from_secs(15 * 60)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_max_and_resets_after_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check("a", t0));
        assert!(rl.check("a", t0));
        assert!(rl.check("a", t0));
        assert!(!rl.check("a", t0 + Duration::from_secs(59)));
        assert!(rl.check("b", t0));
        assert!(rl.check("a", t0 + Duration::from_secs(60)));
    }

    #[test]
    fn lockout_after_five_failures_and_success_resets() {
        let lo = Lockout::new(5, Duration::from_secs(900));
        let t0 = Instant::now();
        for _ in 0..4 {
            lo.record_failure("u", t0);
        }
        assert!(lo.is_locked("u", t0).is_none());
        lo.record_success("u");
        for _ in 0..4 {
            lo.record_failure("u", t0);
        }
        assert!(lo.is_locked("u", t0).is_none());
        lo.record_failure("u", t0);
        let remaining = lo.is_locked("u", t0 + Duration::from_secs(100)).unwrap();
        assert_eq!(remaining, Duration::from_secs(800));
        assert!(lo.is_locked("other", t0).is_none());
        assert!(lo.is_locked("u", t0 + Duration::from_secs(900)).is_none());
        lo.record_failure("u", t0 + Duration::from_secs(901));
        assert!(lo.is_locked("u", t0 + Duration::from_secs(901)).is_none());
    }

    #[test]
    fn try_attempt_counts_up_front() {
        let lo = Lockout::new(5, Duration::from_secs(900));
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(lo.try_attempt("u", t0).is_ok());
        }
        assert_eq!(lo.try_attempt("u", t0), Err(Duration::from_secs(900)));
        lo.record_success("u");
        assert!(lo.try_attempt("u", t0).is_ok());
    }

    #[test]
    fn lockout_survives_pruning_flood() {
        let lo = Lockout::new(5, Duration::from_secs(900));
        let t0 = Instant::now();
        for _ in 0..4 {
            lo.record_failure("victim", t0);
        }
        for i in 0..(PRUNE_THRESHOLD + 10) {
            lo.record_failure(&format!("noise{i}"), t0);
        }
        lo.record_failure("victim", t0);
        assert!(lo.is_locked("victim", t0).is_some());
    }

    #[test]
    fn lockout_prunes_stale_entries() {
        let lo = Lockout::new(5, Duration::from_secs(900));
        let t0 = Instant::now();
        for i in 0..(PRUNE_THRESHOLD + 10) {
            lo.record_failure(&format!("noise{i}"), t0);
        }
        lo.record_failure("late", t0 + Duration::from_secs(901));
        assert!(lo.len() <= 1);
    }
}
