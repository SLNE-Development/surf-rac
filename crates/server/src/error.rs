//! HTTP error type returned by request handlers.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use surf_rac_protocol::{ErrorBody, ErrorCode};

/// An error response with a status, a machine-readable code and a message.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status of the response.
    pub status: StatusCode,
    /// Machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable description sent to the client.
    pub message: String,
    /// Seconds after which a retry may succeed, sent as `Retry-After`.
    pub retry_after_secs: Option<u64>,
}

impl ApiError {
    /// Builds an error from its parts without a retry hint.
    fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    /// 400: the request is malformed or fails validation.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    /// 401: credentials or session token are missing or invalid.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "unauthorized",
        )
    }

    /// 401 for a failed login, without revealing which part was wrong.
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "invalid credentials",
        )
    }

    /// 403: the caller may not act on this resource.
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, "forbidden")
    }

    /// 404: the resource does not exist.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, "not found")
    }

    /// 409: the request conflicts with existing state.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::Conflict, message)
    }

    /// 409: the identity key is registered for another installation.
    pub fn clone_detected() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            ErrorCode::CloneDetected,
            "identity key is registered for another installation",
        )
    }

    /// 426: the client's protocol version is not supported and it must be updated.
    pub fn update_required() -> Self {
        Self::new(
            StatusCode::UPGRADE_REQUIRED,
            ErrorCode::UpdateRequired,
            "protocol version not supported, update required",
        )
    }

    /// 429: too many requests from this client.
    pub fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "too many requests",
        )
    }

    /// 429: the account is locked for `retry_secs` seconds after failed logins.
    pub fn locked(retry_secs: u64) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Locked,
            "account temporarily locked",
        );
        e.retry_after_secs = Some(retry_secs.max(1));
        e
    }

    /// 503: the database is unreachable.
    pub fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "service unavailable",
        )
    }

    /// 500: logs `err` and returns a generic message to the client.
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error",
        )
    }
}

impl From<sqlx::Error> for ApiError {
    /// Maps connection failures to 503 and every other database error to 500.
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) | sqlx::Error::PoolClosed => {
                tracing::warn!(error = %err, "database unavailable");
                Self::unavailable()
            }
            other => Self::internal(other),
        }
    }
}

impl IntoResponse for ApiError {
    /// Renders the error as an [`ErrorBody`] JSON response.
    fn into_response(self) -> Response {
        let mut res = (
            self.status,
            Json(ErrorBody {
                error: self.code,
                message: self.message,
            }),
        )
            .into_response();
        if let Some(secs) = self.retry_after_secs {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}
