//! Registration, login, logout and session tests.

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

#[sqlx::test(migrations = "./migrations")]
async fn register_with_invite_then_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = app.invite().await;
    let res = app.register(&code, "alice", PASSWORD).await;
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"username": "alice"}));

    let res = app.login("alice", PASSWORD, "10.0.0.1").await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["token"].as_str().unwrap().len() >= 43);
    assert!(body["expires_at"].is_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn invite_is_single_use(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = app.invite().await;
    assert_eq!(app.register(&code, "alice", PASSWORD).await.status(), 201);
    let res = app.register(&code, "bob", PASSWORD).await;
    assert_eq!(res.status(), 400);
    assert_eq!(error_code(res).await, "bad_request");
}

#[sqlx::test(migrations = "./migrations")]
async fn invite_double_redeem_single_winner(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = app.invite().await;
    let (a, b) = tokio::join!(
        app.register(&code, "alice", PASSWORD),
        app.register(&code, "bob", PASSWORD)
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [201, 400]);
    let users: i64 = sqlx::query_scalar("select count(*) from users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_invite_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = app.invite().await;
    sqlx::query("update invites set expires_at = now() - interval '1 second'")
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(app.register(&code, "alice", PASSWORD).await.status(), 400);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_invite_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    assert_eq!(app.register("nope", "alice", PASSWORD).await.status(), 400);
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_username_conflict_keeps_invite(pool: PgPool) {
    let app = common::spawn(pool).await;
    let first = app.invite().await;
    assert_eq!(app.register(&first, "alice", PASSWORD).await.status(), 201);
    let second = app.invite().await;
    let res = app.register(&second, "alice", PASSWORD).await;
    assert_eq!(res.status(), 409);
    assert_eq!(error_code(res).await, "conflict");
    assert_eq!(app.register(&second, "bob", PASSWORD).await.status(), 201);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_username_and_short_password_rejected(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = app.invite().await;
    for name in ["al", "Alice", "a b c", "x".repeat(33).as_str(), "élan"] {
        assert_eq!(app.register(&code, name, PASSWORD).await.status(), 400, "{name}");
    }
    assert_eq!(app.register(&code, "alice", "short").await.status(), 400);
    let long = "p".repeat(257);
    assert_eq!(app.register(&code, "alice", &long).await.status(), 400);
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
    assert_eq!(app.register(&code, "alice", PASSWORD).await.status(), 201);
}

#[sqlx::test(migrations = "./migrations")]
async fn login_wrong_password_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    let res = app.login("alice", "wrong password!", "10.0.0.2").await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "invalid credentials");
}

#[sqlx::test(migrations = "./migrations")]
async fn login_unknown_user_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.login("ghost", PASSWORD, "10.0.0.3").await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "invalid credentials");
}

#[sqlx::test(migrations = "./migrations")]
async fn account_locks_after_five_failures(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    for i in 0..5 {
        let ip = format!("10.1.0.{i}");
        assert_eq!(app.login("alice", "wrong password!", &ip).await.status(), 401);
    }
    let res = app.login("alice", PASSWORD, "10.1.1.1").await;
    assert_eq!(res.status(), 429);
    assert!(res.headers().contains_key("retry-after"));
    assert_eq!(error_code(res).await, "locked");
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_failures_cannot_exceed_lockout(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    let attempts = (0..10).map(|i| {
        let ip = format!("10.6.0.{i}");
        let app = &app;
        async move { app.login("alice", "wrong password!", &ip).await.status().as_u16() }
    });
    let statuses = futures_util::future::join_all(attempts).await;
    let verified = statuses.iter().filter(|s| **s == 401).count();
    assert!(verified <= 5, "{statuses:?}");
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 10 - verified);
}

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

#[sqlx::test(migrations = "./migrations")]
async fn register_ip_rate_limited(pool: PgPool) {
    let app = common::spawn(pool).await;
    for _ in 0..5 {
        let res = app
            .register_from("nope", "alice", PASSWORD, "10.4.0.1")
            .await;
        assert_eq!(res.status(), 400);
    }
    let res = app.register_from("nope", "alice", PASSWORD, "10.4.0.1").await;
    assert_eq!(res.status(), 429);
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_revokes_token(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    assert_eq!(probe(&app, &token).await, 204);
    assert_eq!(probe(&app, &token).await, 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_or_garbage_token_401(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.client.post(app.url("/v1/logout")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(probe(&app, "garbage").await, 401);
}

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

#[sqlx::test(migrations = "./migrations")]
async fn session_use_slides_expiry(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    sqlx::query(
        "update sessions set last_used_at = now() - interval '2 hours', \
         expires_at = now() + interval '1 day'",
    )
    .execute(&app.pool)
    .await
    .unwrap();
    let state = app.state.clone();
    let user = surf_rac_server::sessions::authenticate(&state.db, &token)
        .await
        .unwrap();
    assert!(user.is_some());
    let days: f64 = sqlx::query_scalar(
        "select extract(epoch from expires_at - now())::float8 / 86400 from sessions",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(days > 29.9, "{days}");
}

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
