//! Router-specific error types and conversions.

use axum::response::{IntoResponse, Response};
use std::error::Error;

/// HTTP error responses.
#[derive(Debug)]
pub enum ResponseError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    InternalServerError(String),
}

use ResponseError::*;

/// Convert a boxed error that is Send + Sync into a ResponseError.
impl From<Box<dyn Error + Send + Sync>> for ResponseError {
    fn from(error: Box<dyn Error + Send + Sync>) -> Self {
        ResponseError::InternalServerError(error.to_string())
    }
}

/// Convert a ResponseError into an HTTP response.
impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        use axum::http::StatusCode;

        let (status, msg) = match self {
            BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        // Capitalize the first character of the message
        let capitalized_msg = match msg.chars().next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + &msg[f.len_utf8()..],
        };

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!("{capitalized_msg}");
        } else {
            tracing::warn!("{capitalized_msg}");
        }

        let body = format!("{status}\n\n{capitalized_msg}");

        (status, body).into_response()
    }
}
