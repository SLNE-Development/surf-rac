//! Admin operations behind the CLI subcommands.
//!
//! Each function returns the text to print.

use std::fmt::Write as _;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;

use crate::accounts::{self, RegisterError};
use crate::crypto;
use crate::sessions;

/// Creates an admin account named `username` with `password`.
pub async fn create_admin(db: &PgPool, username: &str, password: &str) -> anyhow::Result<String> {
    validate(username, password)?;
    let hash = crypto::hash_password(password).map_err(|e| anyhow!("hashing password: {e}"))?;
    match accounts::create_user(db, username, &hash, true).await {
        Ok(_) => Ok(format!("created admin {username}")),
        Err(RegisterError::UsernameTaken) => bail!("username {username} is already taken"),
        Err(err) => Err(err.into()),
    }
}

/// Row of the user listing.
#[derive(sqlx::FromRow)]
struct UserListRow {
    /// Username.
    username: String,
    /// Whether the user is an admin.
    is_admin: bool,
    /// Whether the user is disabled.
    disabled: bool,
    /// Creation time.
    created_at: DateTime<Utc>,
    /// Number of linked devices.
    devices: i64,
}

/// Lists all users with their flags and device counts.
pub async fn list_users(db: &PgPool) -> anyhow::Result<String> {
    let rows: Vec<UserListRow> = sqlx::query_as(
        "select u.username, u.is_admin, u.disabled, u.created_at, \
         (select count(*) from device_links l where l.user_id = u.id) as devices \
         from users u order by u.username",
    )
    .fetch_all(db)
    .await?;
    let mut out = String::from("username\tflags\tdevices\tcreated\n");
    for r in rows {
        let mut flags = Vec::new();
        if r.is_admin {
            flags.push("admin");
        }
        if r.disabled {
            flags.push("disabled");
        }
        let flags = if flags.is_empty() {
            "-".into()
        } else {
            flags.join(",")
        };
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}",
            r.username,
            flags,
            r.devices,
            r.created_at.format("%Y-%m-%d")
        );
    }
    Ok(out)
}

/// Disables or re-enables `username`; disabling also revokes all their sessions.
pub async fn set_disabled(db: &PgPool, username: &str, disabled: bool) -> anyhow::Result<String> {
    let id = user_id(db, username).await?;
    sqlx::query("update users set disabled = $2 where id = $1")
        .bind(id)
        .bind(disabled)
        .execute(db)
        .await?;
    if disabled {
        let n = sessions::revoke_all_for_user(db, id).await?;
        Ok(format!("disabled {username}, revoked {n} sessions"))
    } else {
        Ok(format!("enabled {username}"))
    }
}

/// Parses a 9-digit device ID, ignoring any whitespace between or around the digits.
///
/// Accepts both `386928003` and the grouped form `386 928 003` that clients show.
pub fn parse_device_id(input: &str) -> anyhow::Result<DeviceId> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    digits
        .parse()
        .map_err(|err| anyhow!("invalid device id {input:?}: {err}"))
}

/// Disables or re-enables `device`.
///
/// Setting the flag to the value it already has succeeds. New connections of
/// a disabled device are refused with `device_disabled`; a connection that is
/// open is sent a `device_disabled` error and closed at its next periodic
/// re-check. Fails when no device has the ID.
pub async fn set_device_disabled(
    db: &PgPool,
    device: DeviceId,
    disabled: bool,
) -> anyhow::Result<String> {
    let updated = sqlx::query("update devices set disabled = $2 where id = $1")
        .bind(i64::from(device.get()))
        .bind(disabled)
        .execute(db)
        .await?
        .rows_affected();
    if updated == 0 {
        bail!("no device with id {device}");
    }
    if disabled {
        Ok(format!(
            "disabled device {device}; its open connection is closed within a minute"
        ))
    } else {
        Ok(format!("enabled device {device}"))
    }
}

/// Sets a new password for `username` and revokes all their sessions.
pub async fn reset_password(db: &PgPool, username: &str, password: &str) -> anyhow::Result<String> {
    if !accounts::valid_password(password) {
        bail!("password must be 10 to 256 characters");
    }
    let id = user_id(db, username).await?;
    let hash = crypto::hash_password(password).map_err(|e| anyhow!("hashing password: {e}"))?;
    sqlx::query("update users set password_hash = $2 where id = $1")
        .bind(id)
        .bind(hash)
        .execute(db)
        .await?;
    let n = sessions::revoke_all_for_user(db, id).await?;
    Ok(format!(
        "password of {username} reset, revoked {n} sessions"
    ))
}

/// Revokes every session of `username`.
pub async fn revoke_sessions(db: &PgPool, username: &str) -> anyhow::Result<String> {
    let id = user_id(db, username).await?;
    let n = sessions::revoke_all_for_user(db, id).await?;
    Ok(format!("revoked {n} sessions of {username}"))
}

/// Returns the ID of `username`, or an error if there is no such user.
async fn user_id(db: &PgPool, username: &str) -> anyhow::Result<i64> {
    sqlx::query_scalar("select id from users where username = $1")
        .bind(username)
        .fetch_optional(db)
        .await?
        .with_context(|| format!("no user named {username}"))
}

/// Checks `username` and `password` against the account rules.
fn validate(username: &str, password: &str) -> anyhow::Result<()> {
    if !accounts::valid_username(username) {
        bail!("username must be 3 to 32 characters of a-z, 0-9, '.', '_' or '-'");
    }
    if !accounts::valid_password(password) {
        bail!("password must be 10 to 256 characters");
    }
    Ok(())
}
