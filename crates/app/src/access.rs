//! Whether a host admits a session request: unattended password checks with
//! host-wide brute-force lockout, falling back to asking the person at the host.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use surf_rac_protocol::DeviceId;

/// Wrong unattended passwords, from any viewers, that lock password access.
pub const FAILURE_LIMIT: usize = 5;

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

/// Host-wide brute-force bookkeeping for unattended passwords, held in memory.
#[derive(Debug, Default)]
pub struct HostLockout {
    /// Times of wrong passwords from any viewer that have not expired, oldest first.
    failures: VecDeque<Instant>,
    /// End of the current lockout, if any.
    locked_until: Option<Instant>,
}

impl HostLockout {
    /// Returns whether password access is locked at `now`.
    pub fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    /// Counts a wrong password at `now`. A failure expires [`LOCKOUT`] after it
    /// was recorded; the [`FAILURE_LIMIT`]th unexpired failure locks password
    /// access for [`LOCKOUT`].
    pub fn record_failure(&mut self, now: Instant) {
        while self
            .failures
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= LOCKOUT)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        if self.failures.len() >= FAILURE_LIMIT {
            self.failures.clear();
            self.locked_until = Some(now + LOCKOUT);
        }
    }
}

/// Returns whether viewers may offer the unattended password: unattended
/// access is enabled, a password is set and password access is not locked out.
pub fn password_access_available(enabled: bool, password_set: bool, locked: bool) -> bool {
    enabled && password_set && !locked
}

/// Longest device name shown, in characters.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// Decides a request like [`decide`] and also returns whether password access
/// is still available afterwards.
///
/// `enabled` is the unattended-access toggle and `password_set` whether a
/// password hash exists.
pub fn decide_and_gate(
    check: PasswordCheck,
    enabled: bool,
    password_set: bool,
    lockout: &mut HostLockout,
    now: Instant,
) -> (Decision, bool) {
    let decision = decide(check, enabled && password_set, lockout, now);
    let available = password_access_available(enabled, password_set, lockout.is_locked(now));
    (decision, available)
}

/// Returns `raw`, a device name chosen by the viewer, made safe to display.
///
/// Control characters and invisible or bidirectional formatting characters are
/// removed, runs of whitespace become one space, and the result is cut to
/// [`MAX_DEVICE_NAME_LEN`] characters. An empty result is replaced by the
/// viewer's ID.
pub fn sanitize_device_name(raw: &str, viewer: DeviceId) -> String {
    let spaced: String = raw
        .chars()
        .filter_map(|c| {
            if c.is_whitespace() {
                Some(' ')
            } else if c.is_control() || is_format_char(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    let joined = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut: String = joined.chars().take(MAX_DEVICE_NAME_LEN).collect();
    let cleaned = cut.trim_end();
    if cleaned.is_empty() {
        viewer.to_string()
    } else {
        cleaned.to_string()
    }
}

/// Returns whether `c` is an invisible or bidirectional formatting character.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}')
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

/// Checks the password a viewer sent against the host's password `hash`.
///
/// `received` is the opened password, or `None` when it could not be opened.
/// Without a hash every password is wrong.
pub fn check_password(received: Option<&str>, hash: Option<&str>) -> PasswordCheck {
    match (received, hash) {
        (None, _) => PasswordCheck::Unreadable,
        (Some(password), Some(hash)) if verify_password(password, hash) => PasswordCheck::Correct,
        (Some(_), _) => PasswordCheck::Wrong,
    }
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
    /// Password admission is locked for the whole host.
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

/// Decides a request given its password check and whether unattended access
/// is on, updating `lockout`.
///
/// Only a correct password with unattended access on and no lockout admits a
/// viewer; every other case asks the person at the host. Wrong and unreadable
/// passwords count as failures unless password access is already locked.
pub fn decide(
    check: PasswordCheck,
    unattended: bool,
    lockout: &mut HostLockout,
    now: Instant,
) -> Decision {
    if check == PasswordCheck::Absent {
        return Decision::Prompt(PromptNote::None);
    }
    if lockout.is_locked(now) {
        return Decision::Prompt(PromptNote::LockedOut);
    }
    match check {
        PasswordCheck::Absent => Decision::Prompt(PromptNote::None),
        PasswordCheck::Wrong | PasswordCheck::Unreadable => {
            lockout.record_failure(now);
            Decision::Prompt(PromptNote::WrongPassword)
        }
        PasswordCheck::Correct if unattended => Decision::Accept,
        PasswordCheck::Correct => Decision::Prompt(PromptNote::CorrectPassword),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn received_passwords_are_checked_against_the_hash() {
        let hash = hash_password("hunter22").unwrap();
        assert_eq!(
            check_password(Some("hunter22"), Some(&hash)),
            PasswordCheck::Correct
        );
        assert_eq!(
            check_password(Some("hunter23"), Some(&hash)),
            PasswordCheck::Wrong
        );
        assert_eq!(check_password(Some("hunter22"), None), PasswordCheck::Wrong);
        assert_eq!(check_password(None, Some(&hash)), PasswordCheck::Unreadable);
    }

    #[test]
    fn hash_verifies_only_the_right_password() {
        let hash = hash_password("hunter22").unwrap();
        assert!(verify_password("hunter22", &hash));
        assert!(!verify_password("hunter23", &hash));
        assert!(!verify_password("hunter22", "not a hash"));
    }

    #[test]
    fn password_access_follows_toggle_hash_and_lockout() {
        assert!(password_access_available(true, true, false));
        assert!(!password_access_available(false, true, false));
        assert!(!password_access_available(true, false, false));
        assert!(!password_access_available(true, true, true));
    }

    #[test]
    fn decisions() {
        let now = Instant::now();
        let mut lockout = HostLockout::default();
        assert_eq!(
            decide(PasswordCheck::Absent, true, &mut lockout, now),
            Decision::Prompt(PromptNote::None)
        );
        assert_eq!(
            decide(PasswordCheck::Correct, true, &mut lockout, now),
            Decision::Accept
        );
        assert_eq!(
            decide(PasswordCheck::Correct, false, &mut lockout, now),
            Decision::Prompt(PromptNote::CorrectPassword)
        );
        assert_eq!(
            decide(PasswordCheck::Wrong, true, &mut lockout, now),
            Decision::Prompt(PromptNote::WrongPassword)
        );
        assert_eq!(
            decide(PasswordCheck::Unreadable, true, &mut lockout, now),
            Decision::Prompt(PromptNote::WrongPassword)
        );
    }

    #[test]
    fn failures_expire_fifteen_minutes_after_they_were_recorded() {
        let mut lockout = HostLockout::default();
        let start = Instant::now();
        for _ in 0..4 {
            lockout.record_failure(start);
        }
        lockout.record_failure(start + LOCKOUT);
        assert!(!lockout.is_locked(start + LOCKOUT));
        for _ in 0..3 {
            lockout.record_failure(start + LOCKOUT);
        }
        assert!(!lockout.is_locked(start + LOCKOUT));
        lockout.record_failure(start + LOCKOUT);
        assert!(lockout.is_locked(start + LOCKOUT));
    }

    #[test]
    fn five_failures_within_the_window_lock_for_fifteen_minutes() {
        let mut lockout = HostLockout::default();
        let start = Instant::now();
        for n in 0..5 {
            lockout.record_failure(start + Duration::from_secs(n * 60));
        }
        let locked_at = start + Duration::from_secs(4 * 60);
        assert!(lockout.is_locked(locked_at));
        assert!(!lockout.is_locked(locked_at + LOCKOUT));
    }

    #[test]
    fn five_wrong_passwords_switch_password_access_off_until_expiry() {
        let now = Instant::now();
        let mut lockout = HostLockout::default();
        let available =
            |l: &HostLockout, at| password_access_available(true, true, l.is_locked(at));
        assert!(available(&lockout, now));
        for _ in 0..5 {
            assert_eq!(
                decide(PasswordCheck::Wrong, true, &mut lockout, now),
                Decision::Prompt(PromptNote::WrongPassword)
            );
        }
        assert!(!available(&lockout, now));
        assert!(available(&lockout, now + LOCKOUT));
    }

    #[test]
    fn device_names_are_cleaned_for_display() {
        let viewer = DeviceId::new(123_456_789).unwrap();
        assert_eq!(sanitize_device_name("Laptop", viewer), "Laptop");
        assert_eq!(sanitize_device_name("a\u{0}b\u{7}c\nd", viewer), "abc d");
        assert_eq!(
            sanitize_device_name("Admin\u{202E}txt.exe\u{200B}\u{2066}", viewer),
            "Admintxt.exe"
        );
        assert_eq!(sanitize_device_name("  a \t  b  ", viewer), "a b");
        assert_eq!(
            sanitize_device_name(&"x".repeat(200), viewer)
                .chars()
                .count(),
            64
        );
        assert_eq!(sanitize_device_name("", viewer), "123456789");
        assert_eq!(sanitize_device_name("\u{202E}\u{0} ", viewer), "123456789");
    }
}
