//! Admin operations behind the CLI subcommands.
//!
//! Each function returns the text to print. Invite codes are printed only
//! when created and never stored in plaintext.

use std::fmt::Write as _;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::accounts::{self, RegisterError};
use crate::crypto;
use crate::sessions;

/// Label stored as `created_by` for invites minted through the CLI.
const CLI_CREATOR: &str = "admin-cli";

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

/// Creates an invite valid for `expires_hours` hours and returns a line ending with its code.
pub async fn create_invite(db: &PgPool, expires_hours: i64) -> anyhow::Result<String> {
    if expires_hours <= 0 {
        bail!("expiry must be a positive number of hours");
    }
    let expires_at = Utc::now() + Duration::hours(expires_hours);
    let code = accounts::create_invite(db, CLI_CREATOR, Duration::hours(expires_hours)).await?;
    Ok(format!(
        "invite valid until {}: {code}",
        expires_at.format("%Y-%m-%d %H:%M UTC")
    ))
}

/// Row of the invite listing.
#[derive(sqlx::FromRow)]
struct InviteRow {
    /// Invite ID, used by `revoke-invite`.
    id: i64,
    /// Creation time.
    created_at: DateTime<Utc>,
    /// Expiry time.
    expires_at: DateTime<Utc>,
    /// Redemption time, if redeemed.
    used_at: Option<DateTime<Utc>>,
    /// Username that redeemed it, if any.
    used_by: Option<String>,
}

/// Lists all invites with their status, without codes.
pub async fn list_invites(db: &PgPool) -> anyhow::Result<String> {
    let rows: Vec<InviteRow> = sqlx::query_as(
        "select i.id, i.created_at, i.expires_at, i.used_at, u.username as used_by \
         from invites i left join users u on u.id = i.used_by order by i.id",
    )
    .fetch_all(db)
    .await?;
    let now = Utc::now();
    let mut out = String::from("id\tcreated\texpires\tstatus\n");
    for r in rows {
        let status = match (r.used_at, r.used_by) {
            (Some(at), by) => format!(
                "used {} by {}",
                at.format("%Y-%m-%d %H:%M"),
                by.unwrap_or_else(|| "deleted user".into())
            ),
            (None, _) if r.expires_at <= now => "expired".into(),
            (None, _) => "unused".into(),
        };
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}",
            r.id,
            r.created_at.format("%Y-%m-%d %H:%M"),
            r.expires_at.format("%Y-%m-%d %H:%M"),
            status
        );
    }
    Ok(out)
}

/// Revokes the unused invite `id` by expiring it now.
pub async fn revoke_invite(db: &PgPool, id: i64) -> anyhow::Result<String> {
    let res = sqlx::query(
        "update invites set expires_at = now() where id = $1 and used_at is null and expires_at > now()",
    )
    .bind(id)
    .execute(db)
    .await?;
    if res.rows_affected() == 0 {
        bail!("no active invite with id {id}");
    }
    Ok(format!("revoked invite {id}"))
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
    /// Number of registered devices.
    devices: i64,
}

/// Lists all users with their flags and device counts.
pub async fn list_users(db: &PgPool) -> anyhow::Result<String> {
    let rows: Vec<UserListRow> = sqlx::query_as(
        "select u.username, u.is_admin, u.disabled, u.created_at, \
         (select count(*) from devices d where d.user_id = u.id) as devices \
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
