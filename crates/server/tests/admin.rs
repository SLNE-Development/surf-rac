//! Admin CLI operation tests.

mod common;

use common::{PASSWORD, TestApp};
use sqlx::PgPool;
use surf_rac_server::admin;

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
    admin::create_admin(&app.pool, "root", PASSWORD)
        .await
        .unwrap();
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
async fn list_users_shows_flags_and_linked_devices(pool: PgPool) {
    let app = common::spawn(pool).await;
    admin::create_admin(&app.pool, "root", PASSWORD)
        .await
        .unwrap();
    let alice = app.register_and_login("alice").await;
    let _one = app.linked_device(1, &alice).await;
    let _two = app.linked_device(2, &alice).await;
    let listing = admin::list_users(&app.pool).await.unwrap();
    let root = listing.lines().find(|l| l.starts_with("root\t")).unwrap();
    assert_eq!(root.split('\t').nth(1), Some("admin"));
    assert_eq!(root.split('\t').nth(2), Some("0"));
    let alice = listing.lines().find(|l| l.starts_with("alice\t")).unwrap();
    assert_eq!(alice.split('\t').nth(1), Some("-"));
    assert_eq!(alice.split('\t').nth(2), Some("2"));
}

/// Runs the server binary with `args` and returns its exit status, stdout and stderr.
fn cli(args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_surf-rac-server"))
        .args(args)
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_has_no_invite_commands() {
    let (ok, help, _) = cli(&["--help"]);
    assert!(ok);
    assert!(!help.to_lowercase().contains("invite"), "{help}");
    for command in [
        "create-admin",
        "list-users",
        "disable-user",
        "enable-user",
        "reset-password",
        "revoke-sessions",
    ] {
        assert!(help.contains(command), "{command} missing: {help}");
    }
    for command in ["create-invite", "list-invites", "revoke-invite"] {
        let (ok, _, err) = cli(&[command]);
        assert!(!ok, "{command}");
        assert!(err.contains("unrecognized subcommand"), "{command}: {err}");
    }
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
    admin::set_disabled(&app.pool, "alice", false)
        .await
        .unwrap();
    assert_eq!(app.login("alice", PASSWORD, "10.9.2.1").await.status(), 200);
}

#[sqlx::test(migrations = "./migrations")]
async fn reset_password_revokes_sessions(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    admin::reset_password(&app.pool, "alice", "a brand new password")
        .await
        .unwrap();
    assert_eq!(probe(&app, &token).await, 401);
    assert_eq!(app.login("alice", PASSWORD, "10.9.3.1").await.status(), 401);
    assert_eq!(
        app.login("alice", "a brand new password", "10.9.3.2")
            .await
            .status(),
        200
    );
    assert!(
        admin::reset_password(&app.pool, "alice", "short")
            .await
            .is_err()
    );
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
    assert!(
        admin::reset_password(&pool, "ghost", PASSWORD)
            .await
            .is_err()
    );
    assert!(admin::revoke_sessions(&pool, "ghost").await.is_err());
}
