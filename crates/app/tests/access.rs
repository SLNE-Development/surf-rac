//! Host access decisions on unattended passwords relayed by an in-process signaling server.

#[allow(clippy::collapsible_if)]
#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::{TestEnv, host_event, request_with, start_host};
use sqlx::PgPool;
use surf_rac_app::access::{
    Decision, HostLockout, LOCKOUT, PromptNote, check_password, decide, hash_password, open_prompt,
};
use surf_rac_app::runtime::PromptView;
use surf_rac_protocol::DeviceId;
use surf_rac_session::SessionConfig;
use surf_rac_session::host::{HostEvent, Password};
use surf_rac_session::viewer::RequestOptions;

#[sqlx::test(migrations = "../server/migrations")]
async fn correct_password_is_admitted_and_wrong_one_prompts(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    host.set_password_access(true);
    let hash = hash_password("hunter22").unwrap();
    let mut lockout = HostLockout::default();

    for (password, expected) in [
        ("hunter22", Decision::Accept),
        ("hunter23", Decision::Prompt(PromptNote::WrongPassword)),
    ] {
        let options = RequestOptions {
            password: Some(password.into()),
        };
        let _pending = request_with(&v, h.id, options, SessionConfig::default());
        let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::PasswordReceived { .. })
        })
        .await;
        let HostEvent::PasswordReceived {
            session_id,
            viewer: _,
            password: received,
            ..
        } = ev
        else {
            unreachable!()
        };
        let check = check_password(received.as_ref().map(Password::as_str), Some(&hash));
        assert_eq!(
            decide(check, true, &mut lockout, Instant::now()),
            expected,
            "password {password}"
        );
        host.deny(&session_id).await.unwrap();
    }
}

fn id(n: u32) -> DeviceId {
    DeviceId::new(100_000_000 + n).unwrap()
}

#[test]
fn five_failures_from_five_viewers_lock_the_host() {
    let mut lockout = HostLockout::default();
    let now = Instant::now();
    for _ in 0..4 {
        lockout.record_failure(now);
    }
    assert!(!lockout.is_locked(now));
    lockout.record_failure(now);
    assert!(lockout.is_locked(now));
}

#[test]
fn wrong_passwords_from_different_viewers_lock_and_refuse_the_right_one() {
    let mut lockout = HostLockout::default();
    let now = Instant::now();
    for n in 0..5 {
        let viewer = id(n);
        let check = check_password(Some("nope"), Some(&hash_password("hunter22").unwrap()));
        assert_eq!(
            decide(check, true, &mut lockout, now),
            Decision::Prompt(PromptNote::WrongPassword),
            "viewer {viewer}"
        );
    }
    assert_eq!(
        decide(
            surf_rac_app::access::PasswordCheck::Correct,
            true,
            &mut lockout,
            now
        ),
        Decision::Prompt(PromptNote::LockedOut)
    );
}

#[test]
fn lock_ends_after_fifteen_minutes() {
    let mut lockout = HostLockout::default();
    let now = Instant::now();
    for _ in 0..5 {
        lockout.record_failure(now);
    }
    assert_eq!(LOCKOUT, Duration::from_secs(15 * 60));
    assert!(lockout.is_locked(now + LOCKOUT - Duration::from_secs(1)));
    assert!(!lockout.is_locked(now + LOCKOUT));
    assert_eq!(
        decide(
            surf_rac_app::access::PasswordCheck::Correct,
            true,
            &mut lockout,
            now + LOCKOUT
        ),
        Decision::Accept
    );
}

#[test]
fn attended_accept_works_while_locked() {
    let mut lockout = HostLockout::default();
    let now = Instant::now();
    for _ in 0..5 {
        lockout.record_failure(now);
    }
    assert_eq!(
        decide(
            surf_rac_app::access::PasswordCheck::Absent,
            true,
            &mut lockout,
            now
        ),
        Decision::Prompt(PromptNote::None)
    );
}

fn prompt(session: &str, viewer: DeviceId) -> PromptView {
    PromptView {
        session_id: session.into(),
        viewer,
        name: "Laptop".into(),
        alias: None,
        fingerprint: "ab".into(),
        note: PromptNote::None,
    }
}

#[test]
fn duplicate_request_from_one_viewer_leaves_one_prompt() {
    let mut prompts = Vec::new();
    assert!(open_prompt(&mut prompts, prompt("s1", id(1))).is_empty());
    assert!(open_prompt(&mut prompts, prompt("s3", id(2))).is_empty());
    let replaced = open_prompt(&mut prompts, prompt("s2", id(1)));
    assert_eq!(replaced, vec!["s1".to_string()]);
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts.iter().filter(|p| p.viewer == id(1)).count(), 1);
    assert!(prompts.iter().any(|p| p.session_id == "s2"));
}
