//! Device registration, re-binding and lookup in the database.

use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::PgPool;
use surf_rac_protocol::DeviceId;

use crate::crypto::{random_token, sha256};

/// Attempts at finding an unused random device ID before giving up.
const ID_ATTEMPTS: usize = 10;

/// Result of a successful registration.
#[derive(Debug, Clone)]
pub struct Registered {
    /// The device's ID.
    pub device_id: DeviceId,
    /// The new plaintext device secret.
    pub secret: String,
    /// True when an existing device was re-bound.
    pub rebound: bool,
}

/// Why a registration was refused.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// The given device ID does not exist.
    #[error("device not found")]
    NotFound,
    /// The given device ID belongs to another account.
    #[error("device belongs to another account")]
    Forbidden,
    /// Another device of this account already has the fingerprint.
    #[error("fingerprint already registered for another device of this account")]
    FingerprintInUse,
    /// No unused device ID was found.
    #[error("could not allocate a device id")]
    IdExhausted,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// A device row as listed to its owner.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    /// Device ID.
    pub id: i64,
    /// Device name.
    pub name: String,
    /// When the device last connected or disconnected.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Returns true when `fingerprint` is 64 lowercase hex characters.
pub fn valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Returns true when `name` has 1 to 64 characters.
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.chars().count())
}

/// Converts a database ID into a [`DeviceId`]; IDs are range-checked by the schema.
pub fn device_id(id: i64) -> DeviceId {
    u32::try_from(id)
        .ok()
        .and_then(DeviceId::new)
        .expect("device ids in the database are 9-digit")
}

/// Registers a device for `user_id`, or re-binds one of the account's devices.
///
/// With `device_id`, that device must belong to the account and gets the new
/// fingerprint, name and secret. Without it, a device of the account with the
/// same fingerprint is re-bound, and otherwise a new device with a random ID
/// is created. Every path issues a fresh secret, invalidating the old one.
pub async fn register(
    db: &PgPool,
    user_id: i64,
    fingerprint: &str,
    name: &str,
    device_id: Option<DeviceId>,
) -> Result<Registered, DeviceError> {
    let secret = random_token(32);
    let secret_hash = sha256(&secret);

    if let Some(id) = device_id {
        let owner: Option<i64> = sqlx::query_scalar("select user_id from devices where id = $1")
            .bind(i64::from(id.get()))
            .fetch_optional(db)
            .await?;
        match owner {
            None => return Err(DeviceError::NotFound),
            Some(owner) if owner != user_id => return Err(DeviceError::Forbidden),
            Some(_) => {}
        }
        sqlx::query(
            "update devices set fingerprint_hash = $3, name = $4, secret_hash = $5 \
             where id = $1 and user_id = $2",
        )
        .bind(i64::from(id.get()))
        .bind(user_id)
        .bind(fingerprint)
        .bind(name)
        .bind(&secret_hash)
        .execute(db)
        .await
        .map_err(|err| match err {
            sqlx::Error::Database(e) if e.is_unique_violation() => DeviceError::FingerprintInUse,
            other => DeviceError::Db(other),
        })?;
        return Ok(Registered {
            device_id: id,
            secret,
            rebound: true,
        });
    }

    for _ in 0..ID_ATTEMPTS {
        let rebound: Option<i64> = sqlx::query_scalar(
            "update devices set name = $3, secret_hash = $4 \
             where user_id = $1 and fingerprint_hash = $2 returning id",
        )
        .bind(user_id)
        .bind(fingerprint)
        .bind(name)
        .bind(&secret_hash)
        .fetch_optional(db)
        .await?;
        if let Some(id) = rebound {
            return Ok(Registered {
                device_id: self::device_id(id),
                secret,
                rebound: true,
            });
        }
        let candidate: i64 = rand::thread_rng().gen_range(100_000_000..=999_999_999);
        let inserted: Option<i64> = sqlx::query_scalar(
            "insert into devices (id, user_id, name, fingerprint_hash, secret_hash) \
             values ($1, $2, $3, $4, $5) on conflict do nothing returning id",
        )
        .bind(candidate)
        .bind(user_id)
        .bind(name)
        .bind(fingerprint)
        .bind(&secret_hash)
        .fetch_optional(db)
        .await?;
        if let Some(id) = inserted {
            return Ok(Registered {
                device_id: self::device_id(id),
                secret,
                rebound: false,
            });
        }
    }
    Err(DeviceError::IdExhausted)
}

/// Returns true when `device` belongs to `user_id` and `secret` is its current secret.
pub async fn authenticate(
    db: &PgPool,
    user_id: i64,
    device: DeviceId,
    secret: &str,
) -> Result<bool, sqlx::Error> {
    let hash: Option<Vec<u8>> =
        sqlx::query_scalar("select secret_hash from devices where id = $1 and user_id = $2")
            .bind(i64::from(device.get()))
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(hash.is_some_and(|h| constant_time_eq(&h, &sha256(secret))))
}

/// Compares two byte strings in time independent of where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Lists the devices of `user_id` ordered by ID.
pub async fn list(db: &PgPool, user_id: i64) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as("select id, name, last_seen_at from devices where user_id = $1 order by id")
        .bind(user_id)
        .fetch_all(db)
        .await
}

/// Deletes `device` if it belongs to `user_id`; returns whether it was deleted.
pub async fn delete(db: &PgPool, user_id: i64, device: DeviceId) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("delete from devices where id = $1 and user_id = $2")
        .bind(i64::from(device.get()))
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Returns whether `device` exists.
pub async fn exists(db: &PgPool, device: DeviceId) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("select exists(select 1 from devices where id = $1)")
        .bind(i64::from(device.get()))
        .fetch_one(db)
        .await
}

/// Records now as `device`'s last-seen time.
pub async fn touch_last_seen(db: &PgPool, device: DeviceId) -> Result<(), sqlx::Error> {
    sqlx::query("update devices set last_seen_at = now() where id = $1")
        .bind(i64::from(device.get()))
        .execute(db)
        .await?;
    Ok(())
}

/// Returns the owning user of `device`, if it exists.
pub async fn owner(db: &PgPool, device: DeviceId) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("select user_id from devices where id = $1")
        .bind(i64::from(device.get()))
        .fetch_optional(db)
        .await
}

/// Sets the public key of `device` if it belongs to `user_id`; returns whether it was set.
pub async fn set_public_key(
    db: &PgPool,
    user_id: i64,
    device: DeviceId,
    key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("update devices set public_key = $3 where id = $1 and user_id = $2")
        .bind(i64::from(device.get()))
        .bind(user_id)
        .bind(&key[..])
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Returns the public key of `device`, if the device exists and has one.
pub async fn public_key(db: &PgPool, device: DeviceId) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let key: Option<Option<Vec<u8>>> =
        sqlx::query_scalar("select public_key from devices where id = $1")
            .bind(i64::from(device.get()))
            .fetch_optional(db)
            .await?;
    Ok(key.flatten())
}
