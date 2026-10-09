//! Per-account contact book in the database.

use sqlx::PgPool;
use surf_rac_protocol::DeviceId;

/// A contact row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContactRow {
    /// Device ID of the contact.
    pub device_id: i64,
    /// Alias the account gave the device.
    pub alias: String,
}

/// Lists the contacts of `user_id` ordered by alias.
pub async fn list(db: &PgPool, user_id: i64) -> Result<Vec<ContactRow>, sqlx::Error> {
    sqlx::query_as(
        "select device_id, alias from contacts where user_id = $1 order by alias, device_id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
}

/// Adds `device` to `user_id`'s contacts or renames it; false when the device does not exist.
pub async fn put(
    db: &PgPool,
    user_id: i64,
    device: DeviceId,
    alias: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "insert into contacts (user_id, device_id, alias) values ($1, $2, $3) \
         on conflict (user_id, device_id) do update set alias = excluded.alias",
    )
    .bind(user_id)
    .bind(i64::from(device.get()))
    .bind(alias)
    .execute(db)
    .await;
    match res {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(e)) if e.is_foreign_key_violation() => Ok(false),
        Err(e) => Err(e),
    }
}

/// Removes `device` from `user_id`'s contacts.
pub async fn delete(db: &PgPool, user_id: i64, device: DeviceId) -> Result<(), sqlx::Error> {
    sqlx::query("delete from contacts where user_id = $1 and device_id = $2")
        .bind(user_id)
        .bind(i64::from(device.get()))
        .execute(db)
        .await?;
    Ok(())
}

/// Returns the users who watch `device`: every account linked to it and every
/// account with it as a contact.
pub async fn watchers(db: &PgPool, device: DeviceId) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "select user_id from device_links where device_id = $1 \
         union select user_id from contacts where device_id = $1",
    )
    .bind(i64::from(device.get()))
    .fetch_all(db)
    .await
}
