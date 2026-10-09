//! Host access decisions on unattended passwords relayed by an in-process signaling server.

#[allow(clippy::collapsible_if)]
#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::{TestEnv, host_event, request, request_with, start_host};
use sqlx::PgPool;
use surf_rac_app::access::{
    Decision, HostLockout, LOCKOUT, PromptNote, check_password, decide, decide_and_gate,
    hash_password, password_access_available,
};
use surf_rac_protocol::DeviceId;
use surf_rac_session::SessionConfig;
use surf_rac_session::host::{HostEvent, Password};
use surf_rac_session::viewer::{RequestError, RequestOptions};

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

#[sqlx::test(migrations = "../server/migrations")]
async fn second_request_from_one_viewer_leaves_one_prompt_and_is_denied(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let mut first = request(&v, h.id, SessionConfig::default());
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::ViewerRequested { .. })
    })
    .await;
    let HostEvent::ViewerRequested { session_id, .. } = ev else {
        unreachable!()
    };
    let second = request(&v, h.id, SessionConfig::default());
    let denied = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("second request ends")
        .unwrap();
    assert!(matches!(denied, Err(RequestError::Denied)));
    let extra = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if let Some(HostEvent::ViewerRequested { .. }) = host_events.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(extra.is_err(), "a second prompt was raised");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut first)
            .await
            .is_err(),
        "the first request is still waiting"
    );
    host.deny(&session_id).await.unwrap();
}

#[sqlx::test(migrations = "../server/migrations")]
async fn fifth_wrong_password_switches_password_access_off_until_the_lock_expires(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let hash = hash_password("hunter22").unwrap();
    let mut lockout = HostLockout::default();
    let start = Instant::now();
    host.set_password_access(true);

    for n in 0..5 {
        let options = RequestOptions {
            password: Some("wrongwrong".into()),
        };
        let _pending = request_with(&v, h.id, options, SessionConfig::default());
        let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::PasswordReceived { .. })
        })
        .await;
        let HostEvent::PasswordReceived {
            session_id,
            password,
            ..
        } = ev
        else {
            unreachable!()
        };
        let check = check_password(password.as_ref().map(Password::as_str), Some(&hash));
        let (decision, available) = decide_and_gate(check, true, true, &mut lockout, start);
        assert_eq!(decision, Decision::Prompt(PromptNote::WrongPassword));
        assert_eq!(available, n < 4, "after failure {}", n + 1);
        host.set_password_access(available);
        host.reject_password(&session_id).await.unwrap();
        host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::ViewerRequested { .. })
        })
        .await;
        host.deny(&session_id).await.unwrap();
    }

    let options = RequestOptions {
        password: Some("hunter22".into()),
    };
    let _pending = request_with(&v, h.id, options.clone(), SessionConfig::default());
    let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(
            e,
            HostEvent::ViewerRequested { .. } | HostEvent::PasswordReceived { .. }
        )
    })
    .await;
    let HostEvent::ViewerRequested { session_id, .. } = ev else {
        panic!("password access should be off while locked");
    };
    host.deny(&session_id).await.unwrap();

    let later = start + LOCKOUT;
    host.set_password_access(password_access_available(
        true,
        true,
        lockout.is_locked(later),
    ));
    let _pending = request_with(&v, h.id, options, SessionConfig::default());
    host_event(&mut host_events, Duration::from_secs(10), |e| {
        matches!(e, HostEvent::PasswordReceived { .. })
    })
    .await;
}
