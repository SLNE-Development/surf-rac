//! In-memory rate limiting and login lockout.
//!
//! State lives in process memory and resets when the server restarts. Each
//! limiter tracks at most [`MAX_KEYS`] keys; stale keys are pruned at most
//! once per [`PRUNE_INTERVAL`] once [`PRUNE_THRESHOLD`] keys are tracked.
//! When the cap is reached, new keys are refused until pruning frees room.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of tracked keys above which stale entries are pruned.
const PRUNE_THRESHOLD: usize = 10_000;

/// Hard cap on tracked keys per limiter.
const MAX_KEYS: usize = 100_000;

/// Minimum time between two pruning passes of one limiter.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Returns the rate-limiting key of a client address.
///
/// IPv4 addresses (including IPv4-mapped IPv6) are used as-is; IPv6 addresses
/// are grouped by their /64 prefix, the smallest block a single client
/// usually controls.
pub fn rate_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// A key-value map with a size cap and rate-limited pruning of stale values.
struct BoundedMap<V> {
    /// Tracked values by key.
    entries: HashMap<String, V>,
    /// When the last pruning pass ran.
    last_prune: Option<Instant>,
}

impl<V: Default> BoundedMap<V> {
    /// Creates an empty map.
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_prune: None,
        }
    }

    /// Returns the value for `key`, inserting a default if there is room.
    ///
    /// Before inserting into a large map, removes the values for which
    /// `is_stale` returns true, at most once per [`PRUNE_INTERVAL`]. Returns
    /// `None` when `key` is new and the map holds [`MAX_KEYS`] values.
    fn get_or_insert(
        &mut self,
        key: &str,
        now: Instant,
        is_stale: impl Fn(&V) -> bool,
    ) -> Option<&mut V> {
        if !self.entries.contains_key(key) {
            let due = self
                .last_prune
                .is_none_or(|t| now.duration_since(t) >= PRUNE_INTERVAL);
            if self.entries.len() >= PRUNE_THRESHOLD && due {
                self.entries.retain(|_, v| !is_stale(v));
                self.last_prune = Some(now);
            }
            if self.entries.len() >= MAX_KEYS {
                return None;
            }
        }
        Some(self.entries.entry(key.to_owned()).or_default())
    }
}

/// Per-key state of a [`RateLimiter`].
#[derive(Default)]
struct Window {
    /// Start of the current window.
    start: Option<Instant>,
    /// Hits counted in the current window.
    hits: u32,
}

/// Fixed-window limiter allowing `max` hits per key within each window.
pub struct RateLimiter {
    /// Hits allowed per window.
    max: u32,
    /// Length of a window.
    window: Duration,
    /// State per key.
    entries: Mutex<BoundedMap<Window>>,
}

impl RateLimiter {
    /// Creates a limiter allowing `max` hits per key every `window`.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            entries: Mutex::new(BoundedMap::new()),
        }
    }

    /// Counts a hit for `key` at `now` and returns whether it is within the limit.
    ///
    /// Returns false for a new key while the limiter is full.
    pub fn check(&self, key: &str, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let window = self.window;
        let stale = |w: &Window| w.start.is_none_or(|s| now.duration_since(s) >= window);
        let Some(w) = entries.get_or_insert(key, now, stale) else {
            return false;
        };
        if stale(w) {
            *w = Window {
                start: Some(now),
                hits: 0,
            };
        }
        if w.hits >= self.max {
            return false;
        }
        w.hits += 1;
        true
    }

    /// Returns the number of tracked keys.
    pub fn tracked_keys(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
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
///
/// Failure counts are forgotten once the key has neither a running lock nor a
/// failure within the lock duration.
pub struct Lockout {
    /// Consecutive failures that trigger a lock.
    max_failures: u32,
    /// How long a lock lasts.
    lock_for: Duration,
    /// State per key.
    entries: Mutex<BoundedMap<LockState>>,
}

impl Lockout {
    /// Creates a lockout that locks for `lock_for` after `max_failures` consecutive failures.
    pub fn new(max_failures: u32, lock_for: Duration) -> Self {
        Self {
            max_failures,
            lock_for,
            entries: Mutex::new(BoundedMap::new()),
        }
    }

    /// Returns the remaining lock time of `key` at `now`, or `None` if it is not locked.
    pub fn is_locked(&self, key: &str, now: Instant) -> Option<Duration> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let until = entries.entries.get(key)?.locked_until?;
        (until > now).then(|| until - now)
    }

    /// Records a failed attempt for `key` at `now`, locking it once the limit is reached.
    ///
    /// Returns false, recording nothing, when `key` is new and the lockout is full.
    pub fn record_failure(&self, key: &str, now: Instant) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.fail(&mut entries, key, now)
    }

    /// Counts a failure for `key` in the already locked `entries`; false when full.
    fn fail(&self, entries: &mut BoundedMap<LockState>, key: &str, now: Instant) -> bool {
        let lock_for = self.lock_for;
        let stale = |s: &LockState| {
            !s.locked_until.is_some_and(|u| u > now)
                && !s.last_failure.is_some_and(|t| now.duration_since(t) < lock_for)
        };
        let Some(state) = entries.get_or_insert(key, now, stale) else {
            return false;
        };
        if state.locked_until.is_some_and(|u| u <= now) {
            *state = LockState::default();
        }
        state.last_failure = Some(now);
        state.failures += 1;
        if state.failures >= self.max_failures {
            state.failures = 0;
            state.locked_until = Some(now + self.lock_for);
        }
        true
    }

    /// Reserves an attempt for `key` at `now`, counting it as a failure up front.
    ///
    /// Returns the remaining lock time when `key` is locked, or the full lock
    /// duration when `key` is new and the lockout is full. The check and the
    /// count happen under one lock, so concurrent attempts cannot exceed the
    /// failure limit. A successful attempt must call
    /// [`Lockout::record_success`], which also lifts a lock that this attempt
    /// itself triggered.
    pub fn try_attempt(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = entries.entries.get(key).and_then(|s| s.locked_until)
            && until > now
        {
            return Err(until - now);
        }
        if self.fail(&mut entries, key, now) {
            Ok(())
        } else {
            Err(self.lock_for)
        }
    }

    /// Returns the number of tracked keys.
    pub fn tracked_keys(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
    }

    /// Clears the failure count of `key` after a successful attempt.
    pub fn record_success(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.entries.remove(key);
    }
}

/// All limiters of the server, configured with the fixed production values.
pub struct Limits {
    /// Login attempts per client address: 10 per minute.
    pub login_ip: RateLimiter,
    /// Registration attempts per client address: 5 per minute.
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
    fn rate_limiter_caps_tracked_keys() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert!(rl.check(&format!("k{i}"), t0));
        }
        assert!(!rl.check("one-too-many", t0));
        assert!(rl.check("k0", t0));
        assert!(rl.check("fresh", t0 + Duration::from_secs(61)));
        assert!(rl.tracked_keys() <= 1);
    }

    #[test]
    fn lockout_caps_tracked_keys() {
        let lo = Lockout::new(5, Duration::from_secs(900));
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert!(lo.try_attempt(&format!("u{i}"), t0).is_ok());
        }
        assert!(lo.try_attempt("one-too-many", t0).is_err());
        assert!(lo.try_attempt("u0", t0).is_ok());
        assert_eq!(lo.tracked_keys(), MAX_KEYS);
    }

    #[test]
    fn rate_key_groups_ipv6_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_key(a), rate_key(b));
        assert_ne!(rate_key(a), rate_key(c));
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(rate_key(v4), "10.0.0.1");
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(rate_key(mapped), "10.0.0.1");
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
        assert!(lo.tracked_keys() <= 1);
    }
}
