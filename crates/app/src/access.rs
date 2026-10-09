//! Whether a host admits a session request: unattended password checks with
//! host-wide brute-force lockout, falling back to asking the person at the host.

use std::time::{Duration, Instant};

use crate::runtime::PromptView;
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Wrong unattended passwords, from any viewers, that lock password access.
pub const FAILURE_LIMIT: u32 = 5;

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
    /// Wrong passwords from any viewer since the last lockout.
    failures: u32,
    /// End of the current lockout, if any.
    locked_until: Option<Instant>,
}

impl HostLockout {
    /// Returns whether password access is locked at `now`.
    pub fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    /// Counts a wrong password at `now`; the [`FAILURE_LIMIT`]th failure locks
    /// password access for [`LOCKOUT`].
    pub fn record_failure(&mut self, now: Instant) {
        if self.locked_until.is_some_and(|until| now >= until) {
            self.locked_until = None;
            self.failures = 0;
        }
        self.failures += 1;
        if self.failures >= FAILURE_LIMIT {
            self.failures = 0;
            self.locked_until = Some(now + LOCKOUT);
        }
    }
}

/// Returns whether viewers may offer the unattended password: unattended
/// access is enabled, a password is set, the host is not attended-only and
/// password access is not locked out.
pub fn password_access_available(
    enabled: bool,
    password_set: bool,
    attended_only: bool,
    locked: bool,
) -> bool {
    enabled && password_set && !attended_only && !locked
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

/// Opens `prompt`, replacing any open prompt of the same viewer.
///
/// Returns the session IDs of the replaced prompts, whose requests the caller
/// must deny.
pub fn open_prompt(prompts: &mut Vec<PromptView>, prompt: PromptView) -> Vec<String> {
    let mut replaced = Vec::new();
    prompts.retain(|p| {
        let same = p.viewer == prompt.viewer || p.session_id == prompt.session_id;
        if same && p.session_id != prompt.session_id {
            replaced.push(p.session_id.clone());
        }
        !same
    });
    prompts.push(prompt);
    replaced
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
    fn password_access_follows_toggle_hash_attended_only_and_lockout() {
        assert!(password_access_available(true, true, false, false));
        assert!(!password_access_available(false, true, false, false));
        assert!(!password_access_available(true, false, false, false));
        assert!(!password_access_available(true, true, true, false));
        assert!(!password_access_available(true, true, false, true));
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
}
