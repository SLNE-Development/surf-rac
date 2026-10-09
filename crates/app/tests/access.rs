//! Host access decisions on unattended passwords relayed by an in-process signaling server.

#[allow(clippy::collapsible_if)]
#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::{TestEnv, host_event, request_with, start_host};
use sqlx::PgPool;
use surf_rac_app::access::{Decision, Lockout, PromptNote, check_password, decide, hash_password};
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
    let mut lockout = Lockout::default();

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
            viewer,
            password: received,
            ..
        } = ev
        else {
            unreachable!()
        };
        let check = check_password(received.as_ref().map(Password::as_str), Some(&hash));
        assert_eq!(
            decide(check, true, &mut lockout, viewer, Instant::now()),
            expected,
            "password {password}"
        );
        host.deny(&session_id).await.unwrap();
    }
}
