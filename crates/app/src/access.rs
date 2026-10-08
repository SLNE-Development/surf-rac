//! Whether a host admits a session request: unattended password checks with
//! brute-force lockout, falling back to asking the person at the host.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use surf_rac_protocol::DeviceId;

/// Wrong passwords from one viewer device that lock it out.
pub const VIEWER_LIMIT: u32 = 5;

/// Wrong passwords from all viewers within [`WINDOW`] that lock everyone out.
pub const GLOBAL_LIMIT: usize = 20;

/// Window over which wrong passwords count towards [`GLOBAL_LIMIT`].
pub const WINDOW: Duration = Duration::from_secs(15 * 60);

/// How long a lockout lasts.
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);

/// Shortest unattended password a host may set.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Hashes an unattended password with Argon2id and a random salt, in PHC string format.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Returns whether `password` matches `hash`; a malformed hash matches nothing.
pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Failed attempts of one viewer device.
#[derive(Debug, Default)]
struct ViewerFailures {
    /// Wrong passwords since the last success or lockout.
    count: u32,
    /// End of the current lockout, if any.
    locked_until: Option<Instant>,
}

/// Brute-force bookkeeping for unattended passwords, held in memory.
#[derive(Debug, Default)]
pub struct Lockout {
    /// Failures per viewer device.
    viewers: HashMap<DeviceId, ViewerFailures>,
    /// Times of recent failures from any viewer, oldest first.
    recent: VecDeque<Instant>,
    /// End of the current lockout of all viewers, if any.
    global_until: Option<Instant>,
}

impl Lockout {
    /// Returns whether password admission is locked for `viewer` at `now`.
    pub fn locked(&self, viewer: DeviceId, now: Instant) -> bool {
        self.global_until.is_some_and(|until| now < until)
            || self
                .viewers
                .get(&viewer)
                .and_then(|v| v.locked_until)
                .is_some_and(|until| now < until)
    }

    /// Counts a wrong password from `viewer` at `now`, starting lockouts at the limits.
    pub fn fail(&mut self, viewer: DeviceId, now: Instant) {
        let entry = self.viewers.entry(viewer).or_default();
        if entry.locked_until.is_some_and(|until| now >= until) {
            entry.locked_until = None;
        }
        entry.count += 1;
        if entry.count >= VIEWER_LIMIT {
            entry.count = 0;
            entry.locked_until = Some(now + LOCKOUT);
        }
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        if self.recent.len() >= GLOBAL_LIMIT {
            self.recent.clear();
            self.global_until = Some(now + LOCKOUT);
        }
    }

    /// Forgets the failures of `viewer` after a correct password.
    pub fn succeed(&mut self, viewer: DeviceId) {
        self.viewers.remove(&viewer);
    }
}

/// What checking a request's password found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    /// The request offered no password.
    Absent,
    /// The password matches the host's unattended password.
    Correct,
    /// The password does not match, or no unattended password is set.
    Wrong,
    /// The sealed password could not be opened.
    Unreadable,
}

/// Extra information shown with a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptNote {
    /// Nothing to add.
    None,
    /// The viewer supplied the correct password, but unattended access is off.
    CorrectPassword,
    /// The viewer supplied a wrong password.
    WrongPassword,
    /// Password admission is locked for this viewer.
    LockedOut,
}

/// How a host answers a session request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Admit the viewer without asking.
    Accept,
    /// Ask the person at the host.
    Prompt(PromptNote),
}

/// Decides a request from `viewer` given its password check and whether
/// unattended access is on, updating `lockout`.
///
/// Only a correct password with unattended access on and no lockout admits a
/// viewer; every other case asks the person at the host. Wrong and unreadable
/// passwords count as failures unless the viewer is already locked out.
pub fn decide(
    check: PasswordCheck,
    unattended: bool,
    lockout: &mut Lockout,
    viewer: DeviceId,
    now: Instant,
) -> Decision {
    if check == PasswordCheck::Absent {
        return Decision::Prompt(PromptNote::None);
    }
    if lockout.locked(viewer, now) {
        return Decision::Prompt(PromptNote::LockedOut);
    }
    match check {
        PasswordCheck::Absent => Decision::Prompt(PromptNote::None),
        PasswordCheck::Wrong | PasswordCheck::Unreadable => {
            lockout.fail(viewer, now);
            Decision::Prompt(PromptNote::WrongPassword)
        }
        PasswordCheck::Correct => {
            lockout.succeed(viewer);
            if unattended {
                Decision::Accept
            } else {
                Decision::Prompt(PromptNote::CorrectPassword)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use surf_rac_protocol::DeviceId;

    fn id(n: u32) -> DeviceId {
        DeviceId::new(100_000_000 + n).unwrap()
    }

    #[test]
    fn hash_verifies_only_the_right_password() {
        let hash = hash_password("hunter22").unwrap();
        assert!(verify_password("hunter22", &hash));
        assert!(!verify_password("hunter23", &hash));
        assert!(!verify_password("hunter22", "not a hash"));
    }

    #[test]
    fn five_failures_lock_only_that_viewer() {
        let mut lockout = Lockout::default();
        let now = Instant::now();
        for _ in 0..4 {
            lockout.fail(id(1), now);
        }
        assert!(!lockout.locked(id(1), now));
        lockout.fail(id(1), now);
        assert!(lockout.locked(id(1), now));
        assert!(!lockout.locked(id(2), now));
        assert!(!lockout.locked(id(1), now + LOCKOUT));
    }

    #[test]
    fn success_resets_a_viewers_count() {
        let mut lockout = Lockout::default();
        let now = Instant::now();
        for _ in 0..4 {
            lockout.fail(id(1), now);
        }
        lockout.succeed(id(1));
        lockout.fail(id(1), now);
        assert!(!lockout.locked(id(1), now));
    }

    #[test]
    fn twenty_failures_across_viewers_lock_everyone() {
        let mut lockout = Lockout::default();
        let now = Instant::now();
        for n in 0..19 {
            lockout.fail(id(n), now);
        }
        assert!(!lockout.locked(id(99), now));
        lockout.fail(id(19), now);
        assert!(lockout.locked(id(99), now));
        assert!(!lockout.locked(id(99), now + LOCKOUT));
    }

    #[test]
    fn global_window_slides() {
        let mut lockout = Lockout::default();
        let start = Instant::now();
        for n in 0..19 {
            lockout.fail(id(n), start);
        }
        let later = start + WINDOW + Duration::from_secs(1);
        lockout.fail(id(50), later);
        assert!(!lockout.locked(id(99), later));
    }

    #[test]
    fn decisions() {
        let now = Instant::now();
        let mut lockout = Lockout::default();
        assert_eq!(
            decide(PasswordCheck::Absent, true, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::None)
        );
        assert_eq!(
            decide(PasswordCheck::Correct, true, &mut lockout, id(1), now),
            Decision::Accept
        );
        assert_eq!(
            decide(PasswordCheck::Correct, false, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::CorrectPassword)
        );
        assert_eq!(
            decide(PasswordCheck::Wrong, true, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::WrongPassword)
        );
        assert_eq!(
            decide(PasswordCheck::Unreadable, true, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::WrongPassword)
        );
    }

    #[test]
    fn locked_viewer_is_prompted_even_with_the_right_password() {
        let now = Instant::now();
        let mut lockout = Lockout::default();
        for _ in 0..5 {
            decide(PasswordCheck::Wrong, true, &mut lockout, id(1), now);
        }
        assert_eq!(
            decide(PasswordCheck::Correct, true, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::LockedOut)
        );
        assert_eq!(
            decide(PasswordCheck::Wrong, true, &mut lockout, id(1), now),
            Decision::Prompt(PromptNote::LockedOut)
        );
    }
}
