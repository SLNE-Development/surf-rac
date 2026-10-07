//! Session tokens: creation, authentication and revocation.
//!
//! Tokens are 32 random bytes in base64url. Only their SHA-256 is stored. A
//! session expires 30 days after its last use; use is recorded at most once
//! per hour.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::crypto::{random_token, sha256};

/// Lifetime of a session after its last use.
const SESSION_TTL_DAYS: i64 = 30;

/// Minimum age of `last_used_at` before a use extends the session.
const SLIDE_AFTER_MINUTES: i64 = 60;

/// An authenticated user, resolved from a valid session token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// User ID.
    pub user_id: i64,
    /// Username.
    pub username: String,
    /// SHA-256 of the presented token, identifying the session.
    pub token_hash: Vec<u8>,
}

/// Row returned by the authentication query.
#[derive(sqlx::FromRow)]
struct SessionRow {
    /// Owner of the session.
    user_id: i64,
    /// Owner's username.
    username: String,
    /// When the session was last used.
    last_used_at: DateTime<Utc>,
}

/// Creates a session for `user_id` and returns the plaintext token and its expiry.
pub async fn create(db: &PgPool, user_id: i64) -> Result<(String, DateTime<Utc>), sqlx::Error> {
    let token = random_token(32);
    let expires_at = Utc::now() + Duration::days(SESSION_TTL_DAYS);
    sqlx::query("insert into sessions (token_hash, user_id, expires_at) values ($1, $2, $3)")
        .bind(sha256(&token))
        .bind(user_id)
        .bind(expires_at)
        .execute(db)
        .await?;
    Ok((token, expires_at))
}

/// Resolves `token` to its user, or `None` when it is unknown, expired or the user is disabled.
///
/// Extends the session to 30 days from now when it was last used more than an hour ago.
pub async fn authenticate(db: &PgPool, token: &str) -> Result<Option<AuthUser>, sqlx::Error> {
    let token_hash = sha256(token);
    let row: Option<SessionRow> = sqlx::query_as(
        "select s.user_id, u.username, s.last_used_at from sessions s \
         join users u on u.id = s.user_id \
         where s.token_hash = $1 and s.expires_at > now() and not u.disabled",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if Utc::now() - row.last_used_at > Duration::minutes(SLIDE_AFTER_MINUTES) {
        sqlx::query(
            "update sessions set last_used_at = now(), expires_at = $2 where token_hash = $1",
        )
        .bind(&token_hash)
        .bind(Utc::now() + Duration::days(SESSION_TTL_DAYS))
        .execute(db)
        .await?;
    }
    Ok(Some(AuthUser {
        user_id: row.user_id,
        username: row.username,
        token_hash,
    }))
}

/// Returns whether the session `token_hash` is unexpired and its user enabled.
pub async fn is_valid(db: &PgPool, token_hash: &[u8]) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "select exists(select 1 from sessions s join users u on u.id = s.user_id \
         where s.token_hash = $1 and s.expires_at > now() and not u.disabled)",
    )
    .bind(token_hash)
    .fetch_one(db)
    .await
}

/// Deletes the session identified by `token_hash`.
pub async fn revoke(db: &PgPool, token_hash: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("delete from sessions where token_hash = $1")
        .bind(token_hash)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes every session of `user_id` and returns how many were removed.
pub async fn revoke_all_for_user(db: &PgPool, user_id: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("delete from sessions where user_id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}
