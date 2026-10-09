//! Host access decisions on session requests relayed by an in-process signaling server.

#[allow(clippy::collapsible_if)]
#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{TestEnv, host_event, start_host};
use sqlx::PgPool;
use surf_rac_app::access::{Decision, Lockout, PromptNote, check_sealed, decide, hash_password};
use surf_rac_session::SessionConfig;
use surf_rac_session::host::HostEvent;
use surf_rac_session::viewer::{RequestOptions, ViewerSession};

#[sqlx::test(migrations = "../server/migrations")]
async fn correct_password_is_admitted_and_wrong_one_prompts(pool: PgPool) {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let hash = hash_password("hunter22").unwrap();
    let mut lockout = Lockout::default();

    for (password, expected) in [
        ("hunter22", Decision::Accept),
        ("hunter23", Decision::Prompt(PromptNote::WrongPassword)),
    ] {
        let options = RequestOptions {
            password: Some(password.into()),
            host_key: Some(h.keys.public_key()),
        };
        let (signaling, keys, known) = (
            v.signaling.clone(),
            Arc::clone(&v.keys),
            Arc::clone(&v.known),
        );
        let host_id = h.id;
        let _pending = tokio::spawn(async move {
            ViewerSession::request_with(
                signaling,
                keys,
                known,
                host_id,
                options,
                SessionConfig::default(),
            )
            .await
        });
        let ev = host_event(&mut host_events, Duration::from_secs(10), |e| {
            matches!(e, HostEvent::ViewerRequested { .. })
        })
        .await;
        let HostEvent::ViewerRequested {
            session_id,
            viewer,
            viewer_key,
            password: sealed,
            ..
        } = ev
        else {
            unreachable!()
        };
        let check = check_sealed(
            &h.keys,
            h.id,
            &viewer_key,
            &session_id,
            viewer,
            sealed.as_deref(),
            Some(&hash),
        );
        assert_eq!(
            decide(check, true, &mut lockout, viewer, Instant::now()),
            expected,
            "password {password}"
        );
        host.deny(&session_id).await.unwrap();
    }
}
