//! Device registration, challenge authentication and lookup in the database.
//!
//! A device is identified by a random 9-digit ID bound to its Ed25519 identity
//! public key and to the SHA-256 of its hardware fingerprint. Registration
//! needs no account.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::Rng;
use sqlx::PgPool;
use surf_rac_protocol::{CHALLENGE_DOMAIN, DeviceId, register_message};

/// Attempts at finding an unused random device ID before giving up.
const ID_ATTEMPTS: usize = 10;

/// Why a registration or authentication was refused.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// The device ID does not exist.
    #[error("device not found")]
    NotFound,
    /// The device is disabled.
    #[error("device is disabled")]
    Disabled,
    /// The identity key is registered with a different fingerprint.
    #[error("identity key is registered for another installation")]
    CloneDetected,
    /// The challenge signature does not verify against the device's identity key.
    #[error("signature does not verify")]
    BadSignature,
    /// No unused device ID was found.
    #[error("could not allocate a device id")]
    IdExhausted,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// A device row as listed to a linked account.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    /// Device ID.
    pub id: i64,
    /// Device name.
    pub name: String,
    /// When the device last connected or disconnected.
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// The identity a device presents on its connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// The device's Ed25519 identity public key.
    pub public_key: [u8; 32],
    /// The device's name.
    pub name: String,
}

/// Row of the authentication query.
#[derive(sqlx::FromRow)]
struct AuthRow {
    /// Stored identity public key.
    public_key: Vec<u8>,
    /// Stored fingerprint hash.
    fingerprint_hash: String,
    /// Whether the device is disabled.
    disabled: bool,
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

/// Returns true when `key` is a valid Ed25519 public key that is not of small order.
pub fn valid_public_key(key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|k| !k.is_weak())
}

/// Converts a database ID into a [`DeviceId`]; IDs are range-checked by the schema.
pub fn device_id(id: i64) -> DeviceId {
    u32::try_from(id)
        .ok()
        .and_then(DeviceId::new)
        .expect("device ids in the database are 9-digit")
}

/// Checks the registration signature of an installation.
///
/// `signature` must be an Ed25519 signature by `public_key` over
/// [`register_message`] of `public_key`, `fingerprint` and `name`, verified
/// strictly. Fails with [`DeviceError::BadSignature`] otherwise.
pub fn verify_registration(
    public_key: &[u8; 32],
    fingerprint: &str,
    name: &str,
    signature: &[u8; 64],
) -> Result<(), DeviceError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| DeviceError::BadSignature)?;
    key.verify_strict(
        &register_message(public_key, fingerprint, name),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| DeviceError::BadSignature)
}

/// Registers the installation with identity `public_key`, `fingerprint` and `name`.
///
/// A key that is already registered with the same fingerprint keeps its ID and
/// gets the new name. A key that is registered with a different fingerprint is
/// refused with [`DeviceError::CloneDetected`] and its record stays unchanged.
/// An unknown key gets a new random ID.
pub async fn register(
    db: &PgPool,
    public_key: &[u8; 32],
    fingerprint: &str,
    name: &str,
) -> Result<DeviceId, DeviceError> {
    for _ in 0..ID_ATTEMPTS {
        let existing: Option<(i64, String)> =
            sqlx::query_as("select id, fingerprint_hash from devices where public_key = $1")
                .bind(&public_key[..])
                .fetch_optional(db)
                .await?;
        if let Some((id, stored)) = existing {
            if stored != fingerprint {
                return Err(DeviceError::CloneDetected);
            }
            sqlx::query("update devices set name = $2 where id = $1 and fingerprint_hash = $3")
                .bind(id)
                .bind(name)
                .bind(fingerprint)
                .execute(db)
                .await?;
            return Ok(device_id(id));
        }
        let candidate: i64 = rand::thread_rng().gen_range(100_000_000..=999_999_999);
        let inserted: Option<i64> = sqlx::query_scalar(
            "insert into devices (id, public_key, fingerprint_hash, name) \
             values ($1, $2, $3, $4) on conflict do nothing returning id",
        )
        .bind(candidate)
        .bind(&public_key[..])
        .bind(fingerprint)
        .bind(name)
        .fetch_optional(db)
        .await?;
        if let Some(id) = inserted {
            return Ok(device_id(id));
        }
    }
    Err(DeviceError::IdExhausted)
}

/// Returns the Ed25519 identity public key of `device`, if the device exists.
pub async fn identity_key(db: &PgPool, device: DeviceId) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let key: Option<Vec<u8>> = sqlx::query_scalar("select public_key from devices where id = $1")
        .bind(i64::from(device.get()))
        .fetch_optional(db)
        .await?;
    Ok(key.and_then(|k| k.try_into().ok()))
}

/// Returns the identity key and name of `device` for a new connection.
///
/// Fails with [`DeviceError::NotFound`] when the device does not exist and
/// with [`DeviceError::Disabled`] when it is disabled.
pub async fn connect_identity(
    db: &PgPool,
    device: DeviceId,
) -> Result<DeviceIdentity, DeviceError> {
    let row: Option<(Vec<u8>, String, bool)> =
        sqlx::query_as("select public_key, name, disabled from devices where id = $1")
            .bind(i64::from(device.get()))
            .fetch_optional(db)
            .await?;
    let (key, name, disabled) = row.ok_or(DeviceError::NotFound)?;
    if disabled {
        return Err(DeviceError::Disabled);
    }
    Ok(DeviceIdentity {
        public_key: key.try_into().map_err(|_| DeviceError::BadSignature)?,
        name,
    })
}

/// Checks a connect challenge answer of `device`.
///
/// `signature` must be an Ed25519 signature by the device's identity key over
/// [`CHALLENGE_DOMAIN`] followed by `nonce`, verified strictly. Only after it
/// verifies is `fingerprint` compared with the registered fingerprint; a
/// mismatch is [`DeviceError::CloneDetected`].
pub async fn authenticate(
    db: &PgPool,
    device: DeviceId,
    fingerprint: &str,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), DeviceError> {
    let row: Option<AuthRow> =
        sqlx::query_as("select public_key, fingerprint_hash, disabled from devices where id = $1")
            .bind(i64::from(device.get()))
            .fetch_optional(db)
            .await?;
    let row = row.ok_or(DeviceError::NotFound)?;
    if row.disabled {
        return Err(DeviceError::Disabled);
    }
    let key: [u8; 32] = row
        .public_key
        .try_into()
        .map_err(|_| DeviceError::BadSignature)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| DeviceError::BadSignature)?;
    let mut message = CHALLENGE_DOMAIN.to_vec();
    message.extend_from_slice(nonce);
    key.verify_strict(&message, &Signature::from_bytes(signature))
        .map_err(|_| DeviceError::BadSignature)?;
    if row.fingerprint_hash != fingerprint {
        return Err(DeviceError::CloneDetected);
    }
    Ok(())
}

/// Returns whether `device` exists and is not disabled.
pub async fn is_active(db: &PgPool, device: DeviceId) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("select exists(select 1 from devices where id = $1 and not disabled)")
        .bind(i64::from(device.get()))
        .fetch_one(db)
        .await
}

/// Lists the devices linked to `user_id` ordered by ID.
pub async fn list(db: &PgPool, user_id: i64) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as(
        "select d.id, d.name, d.last_seen_at from devices d \
         join device_links l on l.device_id = d.id \
         where l.user_id = $1 order by d.id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
}

/// Removes the link between `user_id` and `device`; returns whether a link existed.
pub async fn unlink(db: &PgPool, user_id: i64, device: DeviceId) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("delete from device_links where user_id = $1 and device_id = $2")
        .bind(user_id)
        .bind(i64::from(device.get()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_order_keys_are_invalid() {
        assert!(!valid_public_key(&[0u8; 32]));
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!valid_public_key(&identity));
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(valid_public_key(key.verifying_key().as_bytes()));
    }

    #[test]
    fn fingerprint_must_be_lowercase_hex() {
        assert!(valid_fingerprint(&"a".repeat(64)));
        assert!(!valid_fingerprint(&"A".repeat(64)));
        assert!(!valid_fingerprint(&"a".repeat(63)));
    }
}
