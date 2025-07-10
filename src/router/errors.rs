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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn test_response_error_variants() {
        let bad_request = ResponseError::BadRequest("bad request".into());
        let unauthorized = ResponseError::Unauthorized("unauthorized".into());
        let forbidden = ResponseError::Forbidden("forbidden".into());
        let not_found = ResponseError::NotFound("not found".into());
        let internal = ResponseError::InternalServerError("internal error".into());

        let cases = vec![
            (bad_request, StatusCode::BAD_REQUEST, "Bad request"),
            (unauthorized, StatusCode::UNAUTHORIZED, "Unauthorized"),
            (forbidden, StatusCode::FORBIDDEN, "Forbidden"),
            (not_found, StatusCode::NOT_FOUND, "Not found"),
            (
                internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            ),
        ];

        for (err, status, msg) in cases {
            let response = err.into_response();
            assert_eq!(response.status(), status);
            // Extract body as string (axum 0.7+)
            let body = response.into_body();
            // Use axum's body::to_bytes if available, otherwise use http_body_util
            // Use http_body_util::BodyExt for to_bytes
            use http_body_util::BodyExt;
            let rt = tokio::runtime::Runtime::new().unwrap();
            let body_bytes = rt.block_on(async { body.collect().await.unwrap().to_bytes() });
            let body_str = String::from_utf8_lossy(&body_bytes);
            assert!(body_str.contains(msg));
        }
    }

    #[test]
    fn test_from_boxed_error() {
        let boxed: Box<dyn Error + Send + Sync> = "some error".to_string().into();
        let err: ResponseError = boxed.into();
        match err {
            ResponseError::InternalServerError(msg) => assert!(msg.contains("some error")),
            _ => panic!("Expected InternalServerError"),
        }
    }
}
