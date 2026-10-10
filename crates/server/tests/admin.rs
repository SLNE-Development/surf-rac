//! Admin CLI operation tests.

mod common;

use std::time::Duration;

use common::ws::{expect_closed, recv, recv_type};
use common::{PASSWORD, TestApp};
use serde_json::json;
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;
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

/// An admin created through the admin operations can log in and is stored with the admin flag.
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

/// Creating an admin rejects an invalid username, a too-short password and a taken username.
#[sqlx::test(migrations = "./migrations")]
async fn create_admin_validates_input(pool: PgPool) {
    assert!(admin::create_admin(&pool, "Root", PASSWORD).await.is_err());
    assert!(admin::create_admin(&pool, "root", "short").await.is_err());
    admin::create_admin(&pool, "root", PASSWORD).await.unwrap();
    assert!(admin::create_admin(&pool, "root", PASSWORD).await.is_err());
}

/// The user listing shows the admin flag and the number of linked devices for each account.
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

/// The CLI help lists every admin command and mentions no invites, and the invite subcommands are
/// rejected as unrecognized.
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
        "disable-device",
        "enable-device",
    ] {
        assert!(help.contains(command), "{command} missing: {help}");
    }
    for command in ["create-invite", "list-invites", "revoke-invite"] {
        let (ok, _, err) = cli(&[command]);
        assert!(!ok, "{command}");
        assert!(err.contains("unrecognized subcommand"), "{command}: {err}");
    }
}

/// Disabling a user deletes all of its sessions, invalidates its token and blocks login.
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

/// Re-enabling a disabled user lets it log in again.
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

/// Resetting a password revokes existing sessions and replaces the old password with the new one,
/// and a too-short new password is rejected.
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

/// Revoking a user's sessions reports the revoked count and invalidates its token.
#[sqlx::test(migrations = "./migrations")]
async fn revoke_sessions_logs_out_everywhere(pool: PgPool) {
    let app = common::spawn(pool).await;
    let token = app.register_and_login("alice").await;
    let out = admin::revoke_sessions(&app.pool, "alice").await.unwrap();
    assert!(out.contains('1'));
    assert_eq!(probe(&app, &token).await, 401);
}

/// Disabling, resetting the password of, or revoking the sessions of an unknown user fails.
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

/// Parses `id` as a device ID, panicking when it is invalid.
fn device(id: &str) -> DeviceId {
    id.parse().unwrap()
}

/// Returns whether the device `id` is flagged as disabled in the database.
async fn device_flag(pool: &PgPool, id: &str) -> bool {
    sqlx::query_scalar("select disabled from devices where id = $1")
        .bind(id.parse::<i64>().unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Returns the HTTP status and `error` code of a refused WebSocket upgrade for `id`.
async fn ws_refusal(app: &TestApp, id: &str) -> (u16, serde_json::Value) {
    let version = surf_rac_protocol::PROTOCOL_VERSION.to_string();
    let refused = app.ws_open(Some(id), Some(&version)).await.err().unwrap();
    let code = refused
        .body
        .as_ref()
        .map(|b| b["error"].clone())
        .unwrap_or_default();
    (refused.status, code)
}

/// Parsing a device ID accepts the plain 9 digits and the spaced form the client shows.
#[test]
fn parse_device_id_accepts_spaces() {
    assert_eq!(
        admin::parse_device_id("386928003").unwrap().get(),
        386_928_003
    );
    assert_eq!(
        admin::parse_device_id("386 928 003").unwrap().get(),
        386_928_003
    );
    assert_eq!(
        admin::parse_device_id(" 386 928003 ").unwrap().get(),
        386_928_003
    );
}

/// Parsing a device ID rejects anything that is not 9 digits in the valid range.
#[test]
fn parse_device_id_rejects_invalid_ids() {
    for bad in [
        "",
        "12345",
        "1234567890",
        "012345678",
        "38692800x",
        "386-928-003",
    ] {
        let err = admin::parse_device_id(bad).unwrap_err().to_string();
        assert!(err.contains("device id"), "{bad}: {err}");
    }
}

/// The CLI refuses an invalid device ID with a clear message and a failing exit status.
#[test]
fn cli_rejects_invalid_device_id() {
    for command in ["disable-device", "enable-device"] {
        let (ok, _, err) = cli(&[command, "12345"]);
        assert!(!ok, "{command}");
        assert!(err.contains("device id"), "{command}: {err}");
    }
}

/// The CLI joins a device ID given as several space-separated groups.
#[test]
fn cli_accepts_device_id_in_groups() {
    let (ok, _, err) = cli(&["disable-device", "386", "928", "003"]);
    assert!(!ok);
    assert!(err.contains("DATABASE_URL"), "{err}");
}

/// Disabling a device sets its flag and refuses its new WebSocket connections.
#[sqlx::test(migrations = "./migrations")]
async fn disable_device_sets_flag_and_refuses_connections(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    let out = admin::set_device_disabled(&app.pool, device(&dev.id), true)
        .await
        .unwrap();
    assert!(out.contains(&dev.id), "{out}");
    assert!(device_flag(&app.pool, &dev.id).await);
    assert_eq!(
        ws_refusal(&app, &dev.id).await,
        (403, json!("device_disabled"))
    );
}

/// Disabling an already disabled device succeeds and leaves it disabled.
#[sqlx::test(migrations = "./migrations")]
async fn disable_device_is_idempotent(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    for _ in 0..2 {
        admin::set_device_disabled(&app.pool, device(&dev.id), true)
            .await
            .unwrap();
    }
    assert!(device_flag(&app.pool, &dev.id).await);
}

/// A connected device receives `device_disabled` and is closed after it is disabled.
#[sqlx::test(migrations = "./migrations")]
async fn disable_device_closes_connected_socket(pool: PgPool) {
    let app = common::spawn_with(pool, |s| {
        s.ws_revalidate_interval = Duration::from_millis(200);
    })
    .await;
    let mut dev = app.online_device(1).await;
    admin::set_device_disabled(&app.pool, device(&dev.id), true)
        .await
        .unwrap();
    let err = recv_type(&mut dev.ws, "error").await;
    assert_eq!(err["code"], "device_disabled");
    expect_closed(&mut dev.ws).await;
}

/// Enabling a disabled device clears its flag and lets it connect again.
#[sqlx::test(migrations = "./migrations")]
async fn enable_device_restores_access(pool: PgPool) {
    let app = common::spawn(pool).await;
    let dev = app.new_device(1).await;
    admin::set_device_disabled(&app.pool, device(&dev.id), true)
        .await
        .unwrap();
    let out = admin::set_device_disabled(&app.pool, device(&dev.id), false)
        .await
        .unwrap();
    assert!(out.contains(&dev.id), "{out}");
    assert!(!device_flag(&app.pool, &dev.id).await);
    let mut ws = app.ws_connect(&dev).await;
    assert_eq!(recv(&mut ws).await["type"], "hello");
}

/// Disabling or enabling an unknown device fails with a message naming the ID.
#[sqlx::test(migrations = "./migrations")]
async fn unknown_device_errors(pool: PgPool) {
    for disabled in [true, false] {
        let err = admin::set_device_disabled(&pool, device("123456789"), disabled)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no device") && err.contains("123456789"),
            "{err}"
        );
    }
}
