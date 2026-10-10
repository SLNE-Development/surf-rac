//! Registration, login, logout, session, contact and presence lookup tests.

mod common;

use common::{PASSWORD, TestApp};
use serde_json::{Value, json};
use sqlx::PgPool;

/// Calls the auth probe (logout) with `token` and returns the status.
async fn probe(app: &TestApp, token: &str) -> u16 {
    app.client
        .post(app.url("/v1/logout"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Returns the `error` code of a JSON error response.
async fn error_code(res: reqwest::Response) -> String {
    let body: Value = res.json().await.unwrap();
    body["error"].as_str().unwrap().to_owned()
}

/// Registration needs no invite, answers 201 with the username, and the new non-admin account can
/// log in and receive a token with an expiry.
#[sqlx::test(migrations = "./migrations")]
async fn open_registration_then_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.register("alice", PASSWORD).await;
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"username": "alice"}));

    let res = app.login("alice", PASSWORD, "10.0.0.1").await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["token"].as_str().unwrap().len() >= 43);
    assert!(body["expires_at"].is_string());
    let is_admin: bool = sqlx::query_scalar("select is_admin from users where username = 'alice'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(!is_admin);
}

/// A registration body that carries an `invite_code` field still succeeds.
#[sqlx::test(migrations = "./migrations")]
async fn registration_ignores_an_invite_code(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app
        .client
        .post(app.url("/v1/register"))
        .header("x-forwarded-for", common::fresh_ip())
        .json(&json!({"invite_code": "x", "username": "alice", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
}

/// Registering a taken username answers 409 `conflict`, while a different name still registers.
#[sqlx::test(migrations = "./migrations")]
async fn duplicate_username_conflict(pool: PgPool) {
    let app = common::spawn(pool).await;
    assert_eq!(app.register("alice", PASSWORD).await.status(), 201);
    let res = app.register("alice", PASSWORD).await;
    assert_eq!(res.status(), 409);
    assert_eq!(error_code(res).await, "conflict");
    assert_eq!(app.register("bob", PASSWORD).await.status(), 201);
}

/// Two simultaneous registrations of one username yield exactly one 201 and one 409, leaving a
/// single user.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_registration_of_one_name_single_winner(pool: PgPool) {
    let app = common::spawn(pool).await;
    let (a, b) = tokio::join!(
        app.register("alice", PASSWORD),
        app.register("alice", PASSWORD)
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [201, 409]);
    assert_eq!(app.count("users", "true").await, 1);
}

/// Malformed usernames, too-short or too-long passwords and non-JSON bodies are rejected with 400
/// `bad_request`, while valid edge-case names and a ten-character password register.
#[sqlx::test(migrations = "./migrations")]
async fn invalid_username_and_password_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    for name in [
        "al",
        "Alice",
        "a b c",
        "x".repeat(33).as_str(),
        "élan",
        "a/b",
    ] {
        let res = app.register(name, PASSWORD).await;
        assert_eq!(res.status(), 400, "{name}");
        assert_eq!(error_code(res).await, "bad_request");
    }
    for name in ["abc", "a.b_c-d9", "x".repeat(32).as_str()] {
        assert_eq!(app.register(name, PASSWORD).await.status(), 201, "{name}");
    }
    let res = app.register("alice", "nine char").await;
    assert_eq!(res.status(), 400);
    assert_eq!(error_code(res).await, "bad_request");
    let long = "p".repeat(257);
    assert_eq!(app.register("alice", &long).await.status(), 400);
    let res = app
        .client
        .post(app.url("/v1/register"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(error_code(res).await, "bad_request");
    assert_eq!(app.register("alice", "ten chars!").await.status(), 201);
    assert_eq!(app.count("users", "true").await, 4);
}

/// Logging in with a wrong password answers 401 with the message `invalid credentials`.
#[sqlx::test(migrations = "./migrations")]
async fn login_wrong_password_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    let res = app.login("alice", "wrong password!", "10.0.0.2").await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "invalid credentials");
}

/// Logging in as an unknown user answers 401 with the same `invalid credentials` message as a wrong
/// password.
#[sqlx::test(migrations = "./migrations")]
async fn login_unknown_user_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.login("ghost", PASSWORD, "10.0.0.3").await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "invalid credentials");
}

/// Five failed logins from different addresses lock the account, so even the correct password then
/// gets 429 `locked` with a Retry-After header.
#[sqlx::test(migrations = "./migrations")]
async fn account_locks_after_five_failures(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    for i in 0..5 {
        let ip = format!("10.1.0.{i}");
        assert_eq!(
            app.login("alice", "wrong password!", &ip).await.status(),
            401
        );
    }
    let res = app.login("alice", PASSWORD, "10.1.1.1").await;
    assert_eq!(res.status(), 429);
    assert!(res.headers().contains_key("retry-after"));
    assert_eq!(error_code(res).await, "locked");
}

/// Of ten simultaneous wrong-password logins at most five reach the password check; the rest are
/// refused with 429.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_failures_cannot_exceed_lockout(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    let attempts = (0..10).map(|i| {
        let ip = format!("10.6.0.{i}");
        let app = &app;
        async move {
            app.login("alice", "wrong password!", &ip)
                .await
                .status()
                .as_u16()
        }
    });
    let statuses = futures_util::future::join_all(attempts).await;
    let verified = statuses.iter().filter(|s| **s == 401).count();
    assert!(verified <= 5, "{statuses:?}");
    assert_eq!(
        statuses.iter().filter(|s| **s == 429).count(),
        10 - verified
    );
}

/// Failed logins to a disabled account take comparable time to wrong-password logins, so timing
/// does not reveal that the account is disabled.
#[sqlx::test(migrations = "./migrations")]
async fn disabled_account_login_costs_a_password_check(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    app.register_and_login("bob").await;
    sqlx::query("update users set disabled = true where username = 'bob'")
        .execute(&app.pool)
        .await
        .unwrap();
    let time = |name: &'static str, ip: &'static str| {
        let app = &app;
        async move {
            let start = std::time::Instant::now();
            for _ in 0..3 {
                app.login(name, "wrong password!", ip).await;
            }
            start.elapsed()
        }
    };
    let wrong = time("alice", "10.7.0.1").await;
    let disabled = time("bob", "10.7.0.2").await;
    assert!(
        disabled.as_secs_f64() >= wrong.as_secs_f64() * 0.3,
        "disabled {disabled:?} vs wrong password {wrong:?}"
    );
}

/// Logins with syntactically invalid usernames fail with 401 without creating any lockout tracking
/// entries.
#[sqlx::test(migrations = "./migrations")]
async fn invalid_username_login_is_not_tracked(pool: PgPool) {
    let app = common::spawn(pool).await;
    let huge = "x".repeat(10_000);
    for name in [huge.as_str(), "UPPER", "a"] {
        assert_eq!(app.login(name, PASSWORD, "10.8.0.1").await.status(), 401);
    }
    assert_eq!(app.state.limits.account_lockout.tracked_keys(), 0);
    assert_eq!(app.state.limits.unknown_lockout.tracked_keys(), 0);
}

/// An unknown username is locked after five failed logins with 429 `locked`, exactly like an
/// existing account.
#[sqlx::test(migrations = "./migrations")]
async fn unknown_username_locks_like_a_real_one(pool: PgPool) {
    let app = common::spawn(pool).await;
    for i in 0..5 {
        let ip = format!("10.8.1.{i}");
        assert_eq!(app.login("ghost", PASSWORD, &ip).await.status(), 401);
    }
    let res = app.login("ghost", PASSWORD, "10.8.2.1").await;
    assert_eq!(res.status(), 429);
    assert_eq!(error_code(res).await, "locked");
}

/// A successful login clears the failure count, so four failures before and four after it never
/// lock the account.
#[sqlx::test(migrations = "./migrations")]
async fn successful_login_resets_failures(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    for _ in 0..4 {
        app.login("alice", "wrong password!", "10.2.0.1").await;
    }
    assert_eq!(app.login("alice", PASSWORD, "10.2.0.2").await.status(), 200);
    for _ in 0..4 {
        app.login("alice", "wrong password!", "10.2.0.3").await;
    }
    assert_eq!(app.login("alice", PASSWORD, "10.2.0.4").await.status(), 200);
}

/// Ten logins from one address exhaust its rate limit and the next gets 429 `rate_limited`, while
/// another address is unaffected.
#[sqlx::test(migrations = "./migrations")]
async fn login_ip_rate_limited(pool: PgPool) {
    let app = common::spawn(pool).await;
    for i in 0..10 {
        let name = format!("ghost{i}");
        assert_eq!(app.login(&name, PASSWORD, "10.3.0.1").await.status(), 401);
    }
    let res = app.login("ghost", PASSWORD, "10.3.0.1").await;
    assert_eq!(res.status(), 429);
    assert_eq!(error_code(res).await, "rate_limited");
    assert_eq!(app.login("ghost", PASSWORD, "10.3.0.2").await.status(), 401);
}

/// Five registrations from one address exhaust its rate limit and the sixth gets 429
/// `rate_limited`, while another address can still register.
#[sqlx::test(migrations = "./migrations")]
async fn register_ip_rate_limited(pool: PgPool) {
    let app = common::spawn(pool).await;
    for i in 0..5 {
        let res = app
            .register_from(&format!("user{i}"), PASSWORD, "10.4.0.1")
            .await;
        assert_eq!(res.status(), 201);
    }
    let res = app.register_from("user9", PASSWORD, "10.4.0.1").await;
    assert_eq!(res.status(), 429);
    assert_eq!(error_code(res).await, "rate_limited");
    assert_eq!(
        app.register_from("user9", PASSWORD, "10.4.0.2")
            .await
            .status(),
        201
    );
}

/// Logging out answers 204 and the same token is refused with 401 afterwards.
#[sqlx::test(migrations = "./migrations")]
async fn logout_revokes_token(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    assert_eq!(probe(&app, &token).await, 204);
    assert_eq!(probe(&app, &token).await, 401);
}

/// An authenticated route answers 401 when the bearer token is missing or garbage.
#[sqlx::test(migrations = "./migrations")]
async fn missing_or_garbage_token_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.client.post(app.url("/v1/logout")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(probe(&app, "garbage").await, 401);
}

/// A token whose session has expired is refused with 401.
#[sqlx::test(migrations = "./migrations")]
async fn expired_session_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    sqlx::query("update sessions set expires_at = now() - interval '1 second'")
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(probe(&app, &token).await, 401);
}

/// Returns the days until the only session expires.
async fn days_left(app: &TestApp) -> f64 {
    sqlx::query_scalar(
        "select extract(epoch from expires_at - now())::float8 / 86400 from sessions",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

/// Authenticating with a session close to expiry extends it to about thirty days from now.
#[sqlx::test(migrations = "./migrations")]
async fn session_use_slides_expiry(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    sqlx::query("update sessions set expires_at = now() + interval '1 day'")
        .execute(&app.pool)
        .await
        .unwrap();
    let user = surf_rac_server::sessions::authenticate(&app.state.db, &token)
        .await
        .unwrap();
    assert_eq!(user.unwrap().username, "alice");
    let days = days_left(&app).await;
    assert!(days > 29.9, "{days}");
}

/// Authenticating with a session extended less than an hour ago leaves its expiry unchanged.
#[sqlx::test(migrations = "./migrations")]
async fn session_used_within_the_hour_keeps_expiry(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    sqlx::query(
        "update sessions set expires_at = now() + interval '30 days' - interval '30 minutes'",
    )
    .execute(&app.pool)
    .await
    .unwrap();
    let user = surf_rac_server::sessions::authenticate(&app.state.db, &token)
        .await
        .unwrap();
    assert!(user.is_some());
    let days = days_left(&app).await;
    assert!(days < 29.99, "{days}");
}

/// Disabling a user blocks new logins and invalidates the existing token.
#[sqlx::test(migrations = "./migrations")]
async fn disabled_user_cannot_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    sqlx::query("update users set disabled = true")
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(app.login("alice", PASSWORD, "10.5.0.1").await.status(), 401);
    assert_eq!(probe(&app, &token).await, 401);
}

/// Contacts can be stored for unregistered device IDs and are listed with their alias and online
/// state.
#[sqlx::test(migrations = "./migrations")]
async fn contacts_may_name_unknown_ids(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let device = app.online_device(1).await;
    assert_eq!(
        app.put_contact(&alice, "123456789", "nobody")
            .await
            .status(),
        204
    );
    assert_eq!(
        app.put_contact(&alice, &device.id, "laptop").await.status(),
        204
    );
    let res = app
        .client
        .get(app.url("/v1/contacts"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!([
            {"device_id": device.id, "alias": "laptop", "online": true},
            {"device_id": "123456789", "alias": "nobody", "online": false},
        ])
    );
}

/// Putting a contact again renames it per account, invalid IDs, empty aliases and bad tokens are
/// refused, and deleting removes only the caller's contact.
#[sqlx::test(migrations = "./migrations")]
async fn contacts_rename_delete_and_validate(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let bob = app.register_and_login("bob").await;
    assert_eq!(
        app.put_contact(&alice, "123456789", "one").await.status(),
        204
    );
    assert_eq!(
        app.put_contact(&alice, "123456789", "two").await.status(),
        204
    );
    assert_eq!(
        app.put_contact(&bob, "123456789", "bobs").await.status(),
        204
    );
    let alias: String = sqlx::query_scalar(
        "select c.alias from contacts c join users u on u.id = c.user_id where u.username = 'alice'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(alias, "two");
    assert_eq!(app.put_contact(&alice, "12345", "x").await.status(), 400);
    assert_eq!(app.put_contact(&alice, "123456789", "").await.status(), 400);
    assert_eq!(
        app.put_contact("garbage", "123456789", "x").await.status(),
        401
    );
    let res = app
        .client
        .delete(app.url("/v1/contacts/123456789"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(app.count("contacts", "true").await, 1);
}

/// The presence lookup reports an online device for a logged-in caller, refuses a caller without a
/// token, and answers 404 for an unknown device.
#[sqlx::test(migrations = "./migrations")]
async fn presence_lookup_needs_a_session(pool: PgPool) {
    let app = common::spawn(pool).await;
    let alice = app.register_and_login("alice").await;
    let device = app.online_device(1).await;
    let url = app.url(&format!("/v1/presence/{}", device.id));
    let res = app
        .client
        .get(&url)
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"device_id": device.id, "online": true}));
    assert_eq!(app.client.get(&url).send().await.unwrap().status(), 401);
    let res = app
        .client
        .get(app.url("/v1/presence/123456789"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
