use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("RoleLogic API error: {0}")]
    RoleLogic(String),

    #[error("Role link not found on RoleLogic")]
    RoleLinkNotFound,

    #[error("Role link user limit reached ({limit})")]
    UserLimitReached { limit: usize },

    #[error("Stripe API error: {0}")]
    StripeApi(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Unauthorized: {0}")]
    UnauthorizedWith(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation failed")]
    ValidationFailed(Vec<FieldError>),

    #[error("Configuration was edited; reload and try again")]
    StaleVersion,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Database(e) => classify_db_error(e),
            AppError::RoleLogic(e) => {
                tracing::error!("RoleLogic API error: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({ "error": "Failed to sync roles" })),
                )
                    .into_response()
            }
            AppError::RoleLinkNotFound => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": "Role link not found" })),
            )
                .into_response(),
            AppError::UserLimitReached { limit } => {
                tracing::warn!("Role link user limit reached: {limit}");
                (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({ "error": "Role link user limit reached" })),
                )
                    .into_response()
            }
            AppError::StripeApi(e) => {
                tracing::error!("Stripe API error: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({ "error": "Failed to reach Stripe" })),
                )
                    .into_response()
            }
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({ "error": "Invalid or missing authorization" })),
            )
                .into_response(),
            AppError::UnauthorizedWith(msg) => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({ "error": msg })),
            )
                .into_response(),
            AppError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, axum::Json(json!({ "error": msg }))).into_response()
            }
            AppError::ValidationFailed(field_errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(json!({
                    "error": "Validation failed",
                    "field_errors": field_errors,
                })),
            )
                .into_response(),
            AppError::StaleVersion => (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "error": "The configuration was edited from another tab. Reload and try again.",
                    "code": "STALE_VERSION",
                })),
            )
                .into_response(),
            AppError::Internal(e) => {
                tracing::error!("Internal error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({ "error": "Internal server error" })),
                )
                    .into_response()
            }
        }
    }
}

/// Map a raw `sqlx::Error` to an HTTP response. Constraint violations are
/// client-causable so they get 4xx codes; everything else falls through to 500
/// with a generic body (we log the real cause but never leak it).
fn classify_db_error(e: sqlx::Error) -> Response {
    if let sqlx::Error::Database(db_err) = &e {
        let code = db_err.code();
        let code_str = code.as_deref().unwrap_or("");
        let constraint = db_err.constraint().unwrap_or("");

        match code_str {
            "23505" => {
                tracing::warn!(constraint, "DB unique-violation: {db_err}");
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "error": "A record with that value already exists.",
                        "code": "UNIQUE_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            "23503" => {
                tracing::warn!(constraint, "DB foreign-key-violation: {db_err}");
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "error": "Operation would violate a referential constraint.",
                        "code": "FOREIGN_KEY_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            "23514" => {
                tracing::warn!(constraint, "DB check-violation: {db_err}");
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({
                        "error": "One or more fields failed a database check.",
                        "code": "CHECK_VIOLATION",
                        "constraint": constraint,
                    })),
                )
                    .into_response();
            }
            "23502" => {
                tracing::warn!(constraint, "DB not-null-violation: {db_err}");
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({
                        "error": "A required field was missing.",
                        "code": "NOT_NULL_VIOLATION",
                    })),
                )
                    .into_response();
            }
            _ => {}
        }
    }

    tracing::error!("Database error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({ "error": "Internal server error" })),
    )
        .into_response()
}
