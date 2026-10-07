//! Request extractors that report failures as [`ApiError`].

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// A JSON request body; malformed bodies become a 400 `bad_request` error.
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    /// Parses the body as JSON into `T`.
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|axum::Json(v)| JsonBody(v))
            .map_err(|rejection: JsonRejection| ApiError::bad_request(rejection.body_text()))
    }
}
