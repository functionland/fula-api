//! Error types and S3 error codes

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// S3 error codes
#[derive(Debug, Clone, Copy)]
pub enum S3ErrorCode {
    AccessDenied,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    EntityTooLarge,
    EntityTooSmall,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketName,
    InvalidDigest,
    InvalidPart,
    InvalidPartOrder,
    InvalidRange,
    InvalidRequest,
    InvalidToken,
    KeyTooLong,
    MalformedXML,
    MethodNotAllowed,
    MissingContentLength,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    NotImplemented,
    OperationAborted,
    PreconditionFailed,
    RequestTimeout,
    RequestTimeTooSkewed,
    SignatureDoesNotMatch,
    SlowDown,
    TooManyBuckets,
}

impl S3ErrorCode {
    /// Get the error code string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::BucketAlreadyExists => "BucketAlreadyExists",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::EntityTooLarge => "EntityTooLarge",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::InternalError => "InternalError",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidDigest => "InvalidDigest",
            Self::InvalidPart => "InvalidPart",
            Self::InvalidPartOrder => "InvalidPartOrder",
            Self::InvalidRange => "InvalidRange",
            Self::InvalidRequest => "InvalidRequest",
            Self::InvalidToken => "InvalidToken",
            Self::KeyTooLong => "KeyTooLong",
            Self::MalformedXML => "MalformedXML",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::MissingContentLength => "MissingContentLength",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::NotImplemented => "NotImplemented",
            Self::OperationAborted => "OperationAborted",
            Self::PreconditionFailed => "PreconditionFailed",
            Self::RequestTimeout => "RequestTimeout",
            Self::RequestTimeTooSkewed => "RequestTimeTooSkewed",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::SlowDown => "SlowDown",
            Self::TooManyBuckets => "TooManyBuckets",
        }
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AccessDenied => StatusCode::FORBIDDEN,
            Self::BucketAlreadyExists | Self::BucketAlreadyOwnedByYou => StatusCode::CONFLICT,
            Self::BucketNotEmpty => StatusCode::CONFLICT,
            Self::EntityTooLarge | Self::EntityTooSmall => StatusCode::BAD_REQUEST,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidAccessKeyId | Self::InvalidToken | Self::SignatureDoesNotMatch => {
                StatusCode::FORBIDDEN
            }
            Self::InvalidArgument
            | Self::InvalidBucketName
            | Self::InvalidDigest
            | Self::InvalidPart
            | Self::InvalidPartOrder
            | Self::InvalidRange
            | Self::InvalidRequest
            | Self::KeyTooLong
            | Self::MalformedXML
            | Self::MissingContentLength => StatusCode::BAD_REQUEST,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::NoSuchBucket | Self::NoSuchKey | Self::NoSuchUpload => StatusCode::NOT_FOUND,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::OperationAborted | Self::PreconditionFailed => StatusCode::CONFLICT,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::RequestTimeTooSkewed => StatusCode::FORBIDDEN,
            Self::SlowDown => StatusCode::TOO_MANY_REQUESTS,
            Self::TooManyBuckets => StatusCode::BAD_REQUEST,
        }
    }
}

/// API error type
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("S3 error: {code:?} - {message}")]
    S3Error {
        code: S3ErrorCode,
        message: String,
        resource: Option<String>,
        request_id: String,
    },

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Core error: {0}")]
    Core(#[from] fula_core::CoreError),

    #[error("Block store error: {0}")]
    BlockStore(#[from] fula_blockstore::BlockStoreError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] fula_crypto::CryptoError),
}

impl ApiError {
    /// Create a new S3 error
    pub fn s3(code: S3ErrorCode, message: impl Into<String>) -> Self {
        Self::S3Error {
            code,
            message: message.into(),
            resource: None,
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create with resource
    pub fn s3_with_resource(
        code: S3ErrorCode,
        message: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::S3Error {
            code,
            message: message.into(),
            resource: Some(resource.into()),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Get the error code
    pub fn error_code(&self) -> S3ErrorCode {
        match self {
            Self::S3Error { code, .. } => *code,
            Self::Internal(_) => S3ErrorCode::InternalError,
            Self::Core(e) => match e {
                fula_core::CoreError::BucketNotFound(_) => S3ErrorCode::NoSuchBucket,
                fula_core::CoreError::BucketAlreadyExists(_) => S3ErrorCode::BucketAlreadyExists,
                fula_core::CoreError::ObjectNotFound { .. } => S3ErrorCode::NoSuchKey,
                fula_core::CoreError::InvalidBucketName(_) => S3ErrorCode::InvalidBucketName,
                fula_core::CoreError::AccessDenied(_) => S3ErrorCode::AccessDenied,
                fula_core::CoreError::PreconditionFailed(_) => S3ErrorCode::BucketNotEmpty,
                _ => S3ErrorCode::InternalError,
            },
            Self::BlockStore(_) | Self::Crypto(_) => S3ErrorCode::InternalError,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.error_code();
        let status = code.status_code();
        let request_id = match &self {
            ApiError::S3Error { request_id, .. } => request_id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{}</Code>
    <Message>{}</Message>
    <RequestId>{}</RequestId>
</Error>"#,
            code.as_str(),
            self.to_string().replace('<', "&lt;").replace('>', "&gt;"),
            request_id
        );

        // Include x-amz-error-code header for S3 compatibility
        // This is especially important for HEAD requests which have no body
        (
            status,
            [
                ("Content-Type", "application/xml"),
                ("x-amz-request-id", request_id.as_str()),
                ("x-amz-error-code", code.as_str()),
            ],
            xml,
        )
            .into_response()
    }
}
