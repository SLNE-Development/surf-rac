//! Admin CLI operation tests.

mod common;

use common::{PASSWORD, TestApp};
use sqlx::PgPool;
use surf_rac_server::admin;

/// Returns the invite code printed by `create_invite` (its last word).
fn code_from(output: &str) -> String {
    output.split_whitespace().last().unwrap().to_owned()
}

/// Returns the status of a logout probe with `token`.
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

#[sqlx::test(migrations = "./migrations")]
async fn create_admin_then_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    admin::create_admin(&app.pool, "root", PASSWORD).await.unwrap();
    assert_eq!(app.login("root", PASSWORD, "10.9.0.1").await.status(), 200);
    let is_admin: bool = sqlx::query_scalar("select is_admin from users where username = 'root'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(is_admin);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_admin_validates_input(pool: PgPool) {
    assert!(admin::create_admin(&pool, "Root", PASSWORD).await.is_err());
    assert!(admin::create_admin(&pool, "root", "short").await.is_err());
    admin::create_admin(&pool, "root", PASSWORD).await.unwrap();
    assert!(admin::create_admin(&pool, "root", PASSWORD).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn create_invite_is_redeemable(pool: PgPool) {
    let app = common::spawn(pool).await;
    let out = admin::create_invite(&app.pool, 1).await.unwrap();
    assert_eq!(app.register(&code_from(&out), "alice", PASSWORD).await.status(), 201);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_invite_rejects_nonpositive_hours(pool: PgPool) {
    assert!(admin::create_invite(&pool, 0).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_invite_blocks_redemption(pool: PgPool) {
    let app = common::spawn(pool).await;
    let code = code_from(&admin::create_invite(&app.pool, 72).await.unwrap());
    let id: i64 = sqlx::query_scalar("select id from invites")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    admin::revoke_invite(&app.pool, id).await.unwrap();
    assert_eq!(app.register(&code, "alice", PASSWORD).await.status(), 400);
    assert!(admin::revoke_invite(&app.pool, id + 100).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_invites_never_prints_code(pool: PgPool) {
    let code = code_from(&admin::create_invite(&pool, 72).await.unwrap());
    let listing = admin::list_invites(&pool).await.unwrap();
    assert!(!listing.contains(&code));
    assert!(listing.contains("unused"));
}

#[sqlx::test(migrations = "./migrations")]
async fn list_users_shows_flags(pool: PgPool) {
    let app = common::spawn(pool).await;
    admin::create_admin(&app.pool, "root", PASSWORD).await.unwrap();
    app.register_and_login("alice").await;
    let listing = admin::list_users(&app.pool).await.unwrap();
    assert!(listing.contains("root") && listing.contains("admin"));
    assert!(listing.contains("alice"));
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_user_revokes_sessions_and_blocks_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    admin::set_disabled(&app.pool, "alice", true).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("select count(*) from sessions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
    assert_eq!(probe(&app, &token).await, 401);
    assert_eq!(app.login("alice", PASSWORD, "10.9.1.1").await.status(), 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn enable_user_restores_login(pool: PgPool) {
    let app = common::spawn(pool).await;
    app.register_and_login("alice").await;
    admin::set_disabled(&app.pool, "alice", true).await.unwrap();
    admin::set_disabled(&app.pool, "alice", false).await.unwrap();
    assert_eq!(app.login("alice", PASSWORD, "10.9.2.1").await.status(), 200);
}

#[sqlx::test(migrations = "./migrations")]
async fn reset_password_revokes_sessions(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    admin::reset_password(&app.pool, "alice", "a brand new password").await.unwrap();
    assert_eq!(probe(&app, &token).await, 401);
    assert_eq!(app.login("alice", PASSWORD, "10.9.3.1").await.status(), 401);
    assert_eq!(
        app.login("alice", "a brand new password", "10.9.3.2").await.status(),
        200
    );
    assert!(admin::reset_password(&app.pool, "alice", "short").await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_sessions_logs_out_everywhere(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let out = admin::revoke_sessions(&app.pool, "alice").await.unwrap();
    assert!(out.contains('1'));
    assert_eq!(probe(&app, &token).await, 401);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_user_errors(pool: PgPool) {
    assert!(admin::set_disabled(&pool, "ghost", true).await.is_err());
    assert!(admin::reset_password(&pool, "ghost", PASSWORD).await.is_err());
    assert!(admin::revoke_sessions(&pool, "ghost").await.is_err());
}
