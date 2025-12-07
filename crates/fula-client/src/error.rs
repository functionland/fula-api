//! Client error types

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// S3 API error
    #[error("S3 error ({code}): {message}")]
    S3Error {
        code: String,
        message: String,
        request_id: Option<String>,
    },

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(#[from] fula_crypto::CryptoError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// XML parsing error
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Object not found
    #[error("Object not found: {bucket}/{key}")]
    NotFound { bucket: String, key: String },

    /// Bucket not found
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Upload failed
    #[error("Upload failed: {0}")]
    UploadFailed(String),

    /// Download failed
    #[error("Download failed: {0}")]
    DownloadFailed(String),
}

impl ClientError {
    /// Parse an S3 error from XML response
    pub fn from_s3_xml(xml: &str, status: u16) -> Self {
        // Simple XML parsing for error responses
        let code = extract_xml_element(xml, "Code").unwrap_or_else(|| format!("HTTP{}", status));
        let message = extract_xml_element(xml, "Message").unwrap_or_else(|| "Unknown error".to_string());
        let request_id = extract_xml_element(xml, "RequestId");

        Self::S3Error {
            code,
            message,
            request_id,
        }
    }

    /// Check if this is a "not found" error
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. } | Self::BucketNotFound(_))
            || matches!(self, Self::S3Error { code, .. } if code == "NoSuchKey" || code == "NoSuchBucket")
    }

    /// Check if this is an access denied error
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::AccessDenied(_))
            || matches!(self, Self::S3Error { code, .. } if code == "AccessDenied")
    }
}

fn extract_xml_element(xml: &str, element: &str) -> Option<String> {
    let start_tag = format!("<{}>", element);
    let end_tag = format!("</{}>", element);
    
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml.find(&end_tag)?;
    
    if start < end {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_error() {
        let xml = r#"<?xml version="1.0"?>
<Error>
    <Code>NoSuchKey</Code>
    <Message>The specified key does not exist.</Message>
    <RequestId>abc123</RequestId>
</Error>"#;

        let error = ClientError::from_s3_xml(xml, 404);
        
        match error {
            ClientError::S3Error { code, message, request_id } => {
                assert_eq!(code, "NoSuchKey");
                assert_eq!(message, "The specified key does not exist.");
                assert_eq!(request_id, Some("abc123".to_string()));
            }
            _ => panic!("Expected S3Error"),
        }
    }
}
