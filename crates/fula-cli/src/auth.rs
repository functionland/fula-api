//! Authentication and authorization
//!
//! Supports two authentication methods:
//! 1. Bearer token: `Authorization: Bearer <jwt>`
//! 2. AWS Signature V4: `Authorization: AWS4-HMAC-SHA256 Credential=JWT:<jwt>/...`
//!
//! The AWS Sig V4 method allows standard S3 clients (boto3, AWS CLI, etc.) to work
//! by embedding the JWT in the access key with a `JWT:` prefix.

use crate::{ApiError, S3ErrorCode};
use crate::state::UserSession;
use axum::http::HeaderMap;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: Option<i64>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<Vec<String>>,
    /// Scopes
    #[serde(default)]
    pub scope: String,
    /// Name
    pub name: Option<String>,
}

/// JWT validation configuration
#[derive(Debug, Clone, Default)]
pub struct JwtValidationConfig {
    /// Expected issuer (if set, tokens must have matching iss claim)
    pub issuer: Option<String>,
    /// Expected audience (if set, tokens must have matching aud claim)
    pub audience: Option<String>,
    /// Clock skew tolerance in seconds (default: 60)
    pub leeway_secs: u64,
}

impl JwtValidationConfig {
    pub fn new() -> Self {
        Self {
            issuer: None,
            audience: None,
            leeway_secs: 60,
        }
    }
    
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }
    
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }
}

/// Validate a JWT token and extract claims
/// Security audit fix #6: Validates issuer and audience when configured
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    validate_token_with_config(token, secret, &JwtValidationConfig::default())
}

/// Validate a JWT token with full configuration
pub fn validate_token_with_config(
    token: &str, 
    secret: &str,
    config: &JwtValidationConfig,
) -> Result<Claims, ApiError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = config.leeway_secs;
    
    // Security audit fix #6: Set issuer validation if configured
    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }
    
    // Security audit fix #6: Set audience validation if configured
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    }
    
    decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::debug!("Token validation failed: {}", e);
            ApiError::s3(S3ErrorCode::InvalidToken, "Invalid or expired token")
        })
}

/// Convert claims to a user session
pub fn claims_to_session(claims: Claims) -> UserSession {
    let scopes: Vec<String> = claims.scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let expires_at = DateTime::from_timestamp(claims.exp, 0)
        .unwrap_or_else(|| Utc::now() + Duration::hours(1));

    // Security audit fix A3: Use UserSession::new() to auto-hash user ID
    UserSession::new(claims.sub, claims.name, scopes, expires_at)
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
}

// ═══════════════════════════════════════════════════════════════════════════════
// AWS SIGNATURE V4 SUPPORT
// ═══════════════════════════════════════════════════════════════════════════════

/// Prefix used to identify JWT-based access keys in AWS Sig V4
pub const JWT_ACCESS_KEY_PREFIX: &str = "JWT:";

/// Result of parsing an AWS Sig V4 Authorization header
#[derive(Debug, Clone)]
pub struct AwsSigV4Auth {
    /// The JWT token extracted from the access key
    pub jwt_token: String,
    /// The credential scope (date/region/service/aws4_request)
    pub credential_scope: String,
    /// Signed headers list
    pub signed_headers: Vec<String>,
    /// The signature (for optional validation)
    pub signature: String,
}

/// Check if an Authorization header is AWS Sig V4 format
pub fn is_aws_sigv4(auth_header: &str) -> bool {
    auth_header.starts_with("AWS4-HMAC-SHA256 ")
}

/// Parse AWS Signature V4 Authorization header and extract JWT
///
/// Expected format:
/// ```text
/// AWS4-HMAC-SHA256 Credential=JWT:eyJhbGci.../20231207/us-east-1/s3/aws4_request,
/// SignedHeaders=host;x-amz-date, Signature=abc123...
/// ```
///
/// The access key must be prefixed with `JWT:` to indicate it contains a JWT token.
pub fn parse_aws_sigv4_header(auth_header: &str) -> Result<AwsSigV4Auth, ApiError> {
    // Must start with AWS4-HMAC-SHA256
    if !auth_header.starts_with("AWS4-HMAC-SHA256 ") {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Invalid AWS Signature V4 format",
        ));
    }

    let params = auth_header.strip_prefix("AWS4-HMAC-SHA256 ").unwrap();

    // Parse Credential=...
    let credential = extract_sigv4_param(params, "Credential")?;
    
    // Parse SignedHeaders=...
    let signed_headers_str = extract_sigv4_param(params, "SignedHeaders")?;
    let signed_headers: Vec<String> = signed_headers_str
        .split(';')
        .map(|s| s.to_string())
        .collect();

    // Parse Signature=...
    let signature = extract_sigv4_param(params, "Signature")?;

    // Credential format: AccessKeyId/date/region/service/aws4_request
    // We expect: JWT:eyJhbGci.../20231207/us-east-1/s3/aws4_request
    let credential_parts: Vec<&str> = credential.splitn(2, '/').collect();
    if credential_parts.len() < 2 {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Invalid credential format",
        ));
    }

    let access_key = credential_parts[0];
    let credential_scope = credential_parts[1].to_string();

    // Check for JWT: prefix
    if !access_key.starts_with(JWT_ACCESS_KEY_PREFIX) {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Access key must start with 'JWT:' prefix for Fula gateway",
        ));
    }

    let jwt_token = access_key
        .strip_prefix(JWT_ACCESS_KEY_PREFIX)
        .unwrap()
        .to_string();

    if jwt_token.is_empty() {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "JWT token is empty",
        ));
    }

    Ok(AwsSigV4Auth {
        jwt_token,
        credential_scope,
        signed_headers,
        signature,
    })
}

/// Extract a parameter value from AWS Sig V4 header
fn extract_sigv4_param(params: &str, name: &str) -> Result<String, ApiError> {
    let prefix = format!("{}=", name);
    
    for part in params.split(", ") {
        let part = part.trim();
        if part.starts_with(&prefix) {
            let value = part.strip_prefix(&prefix).unwrap();
            // Remove trailing comma if present
            let value = value.trim_end_matches(',');
            return Ok(value.to_string());
        }
    }

    // Try without space after comma
    for part in params.split(',') {
        let part = part.trim();
        if part.starts_with(&prefix) {
            let value = part.strip_prefix(&prefix).unwrap();
            return Ok(value.to_string());
        }
    }

    Err(ApiError::s3(
        S3ErrorCode::InvalidToken,
        &format!("Missing {} in AWS Sig V4 header", name),
    ))
}

/// Validate AWS Sig V4 timestamp to prevent replay attacks
///
/// The x-amz-date header must be within 15 minutes of current time.
pub fn validate_sigv4_timestamp(headers: &HeaderMap) -> Result<(), ApiError> {
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidToken, "Missing x-amz-date header"))?;

    // Parse ISO 8601 basic format: 20231207T123456Z
    let timestamp = parse_amz_date(amz_date)?;
    let now = Utc::now().timestamp();
    let diff = (now - timestamp).abs();

    // Allow 15 minute window (900 seconds)
    if diff > 900 {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Request timestamp is outside valid window (15 minutes)",
        ));
    }

    Ok(())
}

/// Parse x-amz-date format (ISO 8601 basic: YYYYMMDDTHHMMSSZ)
fn parse_amz_date(date_str: &str) -> Result<i64, ApiError> {
    // Expected format: 20231207T123456Z
    if date_str.len() != 16 || !date_str.ends_with('Z') {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidToken,
            "Invalid x-amz-date format",
        ));
    }

    let year: i32 = date_str[0..4].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid year in x-amz-date")
    })?;
    let month: u32 = date_str[4..6].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid month in x-amz-date")
    })?;
    let day: u32 = date_str[6..8].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid day in x-amz-date")
    })?;
    let hour: u32 = date_str[9..11].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid hour in x-amz-date")
    })?;
    let minute: u32 = date_str[11..13].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid minute in x-amz-date")
    })?;
    let second: u32 = date_str[13..15].parse().map_err(|_| {
        ApiError::s3(S3ErrorCode::InvalidToken, "Invalid second in x-amz-date")
    })?;

    use chrono::NaiveDate;
    let date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidToken, "Invalid date in x-amz-date"))?;
    let time = chrono::NaiveTime::from_hms_opt(hour, minute, second)
        .ok_or_else(|| ApiError::s3(S3ErrorCode::InvalidToken, "Invalid time in x-amz-date"))?;
    let datetime = chrono::NaiveDateTime::new(date, time);

    Ok(datetime.and_utc().timestamp())
}

/// Extract authentication from Authorization header (Bearer or AWS Sig V4)
///
/// Returns the JWT token regardless of which format was used.
pub fn extract_token_from_header(auth_header: &str, headers: &HeaderMap) -> Result<String, ApiError> {
    // Try Bearer token first
    if let Some(token) = extract_bearer_token(auth_header) {
        return Ok(token.to_string());
    }

    // Try AWS Sig V4
    if is_aws_sigv4(auth_header) {
        let sigv4 = parse_aws_sigv4_header(auth_header)?;
        
        // Validate timestamp for replay protection
        validate_sigv4_timestamp(headers)?;
        
        return Ok(sigv4.jwt_token);
    }

    Err(ApiError::s3(
        S3ErrorCode::InvalidToken,
        "Invalid Authorization header format. Use 'Bearer <jwt>' or AWS Signature V4 with 'JWT:<jwt>' as access key",
    ))
}

/// Hash a user ID for storage (privacy)
pub fn hash_user_id(user_id: &str) -> String {
    use fula_crypto::hashing::hash;
    let h = hash(user_id.as_bytes());
    h.to_hex()[..16].to_string()
}

/// Generate an anonymous user ID for unauthenticated requests
pub fn anonymous_user_id() -> String {
    "anonymous".to_string()
}

/// Create a development/test session
pub fn dev_session() -> UserSession {
    // Security audit fix A3: Use UserSession::new() to auto-hash user ID
    UserSession::new(
        "dev-user".to_string(),
        Some("Development User".to_string()),
        vec!["storage:*".to_string()],
        Utc::now() + Duration::days(365),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn create_test_token(claims: &Claims, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_validate_token() {
        let secret = "test-secret";
        let claims = Claims {
            sub: "user123".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            iat: Some(Utc::now().timestamp()),
            iss: None,
            aud: None,
            scope: "storage:read storage:write".to_string(),
            name: Some("Test User".to_string()),
        };

        let token = create_test_token(&claims, secret);
        let validated = validate_token(&token, secret).unwrap();

        assert_eq!(validated.sub, "user123");
    }

    #[test]
    fn test_expired_token() {
        let secret = "test-secret";
        let claims = Claims {
            sub: "user123".to_string(),
            exp: (Utc::now() - Duration::hours(1)).timestamp(),
            iat: None,
            iss: None,
            aud: None,
            scope: String::new(),
            name: None,
        };

        let token = create_test_token(&claims, secret);
        let result = validate_token(&token, secret);

        assert!(result.is_err());
    }

    #[test]
    fn test_claims_to_session() {
        let claims = Claims {
            sub: "user123".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            iat: None,
            iss: None,
            aud: None,
            scope: "storage:read storage:write".to_string(),
            name: Some("Test User".to_string()),
        };

        let session = claims_to_session(claims);

        assert_eq!(session.user_id, "user123");
        assert!(session.can_read());
        assert!(session.can_write());
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
        assert_eq!(
            extract_bearer_token("bearer abc123"),
            Some("abc123")
        );
        assert_eq!(extract_bearer_token("Basic xyz"), None);
    }

    #[test]
    fn test_hash_user_id() {
        let hash1 = hash_user_id("user123");
        let hash2 = hash_user_id("user123");
        let hash3 = hash_user_id("user456");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16);
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // AWS SIGNATURE V4 TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_aws_sigv4() {
        assert!(is_aws_sigv4("AWS4-HMAC-SHA256 Credential=..."));
        assert!(!is_aws_sigv4("Bearer token"));
        assert!(!is_aws_sigv4("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_parse_aws_sigv4_header_valid() {
        let header = "AWS4-HMAC-SHA256 Credential=JWT:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test/20231207/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123def456";
        
        let result = parse_aws_sigv4_header(header).unwrap();
        
        assert_eq!(result.jwt_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test");
        assert_eq!(result.credential_scope, "20231207/us-east-1/s3/aws4_request");
        assert_eq!(result.signed_headers, vec!["host", "x-amz-date"]);
        assert_eq!(result.signature, "abc123def456");
    }

    #[test]
    fn test_parse_aws_sigv4_header_no_spaces() {
        let header = "AWS4-HMAC-SHA256 Credential=JWT:mytoken/20231207/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-date,Signature=sig123";
        
        let result = parse_aws_sigv4_header(header).unwrap();
        
        assert_eq!(result.jwt_token, "mytoken");
        assert_eq!(result.signature, "sig123");
    }

    #[test]
    fn test_parse_aws_sigv4_header_missing_jwt_prefix() {
        let header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231207/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        
        let result = parse_aws_sigv4_header(header);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aws_sigv4_header_empty_jwt() {
        let header = "AWS4-HMAC-SHA256 Credential=JWT:/20231207/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        
        let result = parse_aws_sigv4_header(header);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_amz_date() {
        let date = "20231207T123456Z";
        let timestamp = parse_amz_date(date).unwrap();
        
        // Verify it's a reasonable timestamp (Dec 7, 2023)
        assert!(timestamp > 1701900000);
        assert!(timestamp < 1702000000);
    }

    #[test]
    fn test_parse_amz_date_invalid() {
        assert!(parse_amz_date("2023-12-07T12:34:56Z").is_err()); // Wrong format
        assert!(parse_amz_date("20231207").is_err()); // Missing time
        assert!(parse_amz_date("20231207T123456").is_err()); // Missing Z
    }

    #[test]
    fn test_extract_token_from_header_bearer() {
        use axum::http::HeaderMap;
        
        let headers = HeaderMap::new();
        let result = extract_token_from_header("Bearer mytoken123", &headers).unwrap();
        
        assert_eq!(result, "mytoken123");
    }

    #[test]
    fn test_extract_token_from_header_sigv4() {
        use axum::http::{HeaderMap, HeaderValue};
        
        let mut headers = HeaderMap::new();
        // Add a current timestamp
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        headers.insert("x-amz-date", HeaderValue::from_str(&amz_date).unwrap());
        
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential=JWT:myjwt123/20231207/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=sig"
        );
        
        let result = extract_token_from_header(&auth, &headers).unwrap();
        
        assert_eq!(result, "myjwt123");
    }

    #[test]
    fn test_extract_token_from_header_invalid() {
        use axum::http::HeaderMap;
        
        let headers = HeaderMap::new();
        
        // Not Bearer or AWS Sig V4
        assert!(extract_token_from_header("Basic xyz", &headers).is_err());
        assert!(extract_token_from_header("Custom auth", &headers).is_err());
    }
}
