//! Users and invite codes in the database.

use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::crypto::{random_token, sha256};

/// A user row as needed for login.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    /// Primary key.
    pub id: i64,
    /// Unique username.
    pub username: String,
    /// argon2id PHC hash of the password.
    pub password_hash: String,
    /// Whether the user is an admin.
    pub is_admin: bool,
    /// Whether the user is disabled and may not log in.
    pub disabled: bool,
}

/// Why a registration was refused.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The invite code is unknown, used, revoked or expired.
    #[error("invalid or expired invite")]
    InvalidInvite,
    /// The username is already taken.
    #[error("username already taken")]
    UsernameTaken,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Returns true when `username` is 3 to 32 characters of `[a-z0-9._-]`.
pub fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Returns true when `password` has 10 to 256 characters.
pub fn valid_password(password: &str) -> bool {
    (10..=256).contains(&password.chars().count())
}

/// Creates a single-use invite valid for `expires_in` and returns its plaintext code.
///
/// Only the SHA-256 of the code is stored.
pub async fn create_invite(
    db: &PgPool,
    created_by: &str,
    expires_in: Duration,
) -> Result<String, sqlx::Error> {
    let code = random_token(16);
    sqlx::query("insert into invites (code_hash, created_by, expires_at) values ($1, $2, $3)")
        .bind(sha256(&code))
        .bind(created_by)
        .bind(Utc::now() + expires_in)
        .execute(db)
        .await?;
    Ok(code)
}

/// Consumes the invite `code` and creates a user in one transaction.
///
/// The invite is claimed with a conditional update, so of two concurrent
/// redemptions exactly one succeeds. If the username is taken the whole
/// transaction rolls back and the invite stays unused.
pub async fn redeem_invite_and_create_user(
    db: &PgPool,
    code: &str,
    username: &str,
    password_hash: &str,
) -> Result<i64, RegisterError> {
    let mut tx = db.begin().await?;
    let invite_id: Option<i64> = sqlx::query_scalar(
        "update invites set used_at = now() \
         where code_hash = $1 and used_at is null and expires_at > now() \
         returning id",
    )
    .bind(sha256(code))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(invite_id) = invite_id else {
        return Err(RegisterError::InvalidInvite);
    };
    let user_id = insert_user(&mut tx, username, password_hash, false).await?;
    sqlx::query("update invites set used_by = $1 where id = $2")
        .bind(user_id)
        .bind(invite_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(user_id)
}

/// Creates a user without an invite and returns its ID.
pub async fn create_user(
    db: &PgPool,
    username: &str,
    password_hash: &str,
    is_admin: bool,
) -> Result<i64, RegisterError> {
    let mut tx = db.begin().await?;
    let id = insert_user(&mut tx, username, password_hash, is_admin).await?;
    tx.commit().await?;
    Ok(id)
}

/// Inserts a user inside `tx`, mapping a unique violation to [`RegisterError::UsernameTaken`].
async fn insert_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    username: &str,
    password_hash: &str,
    is_admin: bool,
) -> Result<i64, RegisterError> {
    sqlx::query_scalar(
        "insert into users (username, password_hash, is_admin) values ($1, $2, $3) returning id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(is_admin)
    .fetch_one(&mut **tx)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if db.is_unique_violation() => RegisterError::UsernameTaken,
        other => RegisterError::Db(other),
    })
}

/// Looks up a user by username.
pub async fn find_user_by_name(
    db: &PgPool,
    username: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as(
        "select id, username, password_hash, is_admin, disabled from users where username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
}
