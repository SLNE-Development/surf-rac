//! User accounts in the database.
//!
//! Accounts are optional: anyone can create one, and it only owns a contact
//! list, device links and its sessions. Devices never belong to an account.

use sqlx::PgPool;

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

/// Creates a user and returns its ID.
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

/// Deletes the user `user_id` and returns whether it existed.
///
/// Its sessions, contacts and device links go with it; devices themselves
/// are never deleted, so a device linked to another account stays linked there.
pub async fn delete_user(db: &PgPool, user_id: i64) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("delete from users where id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Returns the password hash of the user `user_id`, if the user exists.
pub async fn password_hash(db: &PgPool, user_id: i64) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("select password_hash from users where id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
}
