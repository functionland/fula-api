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
use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize a JWT `aud` claim that may be a single string or an array of
/// strings (RFC 7519 §4.1.3), normalizing to `Option<Vec<String>>`.
fn deserialize_aud<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }
    let opt = Option::<StringOrVec>::deserialize(deserializer)?;
    Ok(match opt {
        None => None,
        Some(StringOrVec::One(s)) => Some(vec![s]),
        Some(StringOrVec::Many(v)) => Some(v),
    })
}
use chrono::{DateTime, Utc, Duration};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time
    pub exp: Option<i64>,
    /// Issued at
    pub iat: Option<i64>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience. RFC 7519 §4.1.3 allows `aud` to be EITHER a single string OR an
    /// array of strings. The issuer (pinning-webui) mints it as a single string
    /// ("fula-s3-gateway"); accept both forms so an MCP/connection-bound token
    /// deserializes instead of failing with `invalid type: string, expected a
    /// sequence` (which would 403 every MCP token before the revocation check).
    #[serde(default, deserialize_with = "deserialize_aud")]
    pub aud: Option<Vec<String>>,
    /// Scopes
    #[serde(default)]
    pub scope: String,
    /// Name
    pub name: Option<String>,
    /// JWT ID (P12). Present on scoped MCP tokens (`token_use == "mcp_s3"`);
    /// the revocation key. `serde(default)` so legacy storage tokens (which
    /// carry no `jti`) deserialize unchanged.
    #[serde(default)]
    pub jti: Option<String>,
    /// Token-kind discriminator (P12). A token is a scoped MCP token iff this
    /// equals `Some("mcp_s3")`. `serde(default)` ⇒ legacy storage tokens (no
    /// `token_use`) deserialize as `None` and behave byte-identically.
    #[serde(default)]
    pub token_use: Option<String>,
    /// Scoped MCP authorization claim (P12). Present only on MCP tokens; see
    /// [`crate::mcp_scope`]. `serde(default)` ⇒ absent on storage tokens.
    #[serde(default)]
    pub mcp: Option<McpScopeClaim>,
    /// Connection-binding confirmation claim (L1b, RFC 7800 `cnf`). Present ONLY
    /// on a connection-bound MCP token; carries the MCP connection's X25519
    /// public key (base64), which is the key the connection-revocation deny-list
    /// (`crate::mcp_revocation::McpConnectionRevocationState`) is matched on.
    /// `serde(default)` ⇒ a storage token (or an unbound MCP token) has no `cnf`
    /// and deserializes unchanged. The issuer emits `cnf` as a SIBLING of `mcp`
    /// and only ever as `{ mcp_pub_b64 }`, so a non-MCP token never carries it
    /// (see `pinning-webui/server/mcpTokens.ts::McpCnfClaim`).
    #[serde(default)]
    pub cnf: Option<ConnectionConfirmation>,
}

/// The `cnf` connection-binding claim on a connection-bound MCP-S3 JWT (L1b).
/// Mirrors the issuer's `McpCnfClaim` in `pinning-webui/server/mcpTokens.ts`.
/// The gateway only reads `mcp_pub_b64` to match it against the
/// connection-revocation deny-list; `Serialize` is derived solely so tests can
/// mint connection-bound tokens via the existing `create_test_token` helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfirmation {
    /// The MCP connection's X25519 public key, base64 of the raw 32 bytes. The
    /// issuer normalizes this to a canonical base64 form on both mint and
    /// verify, so it is compared VERBATIM against the revoked-pubkeys feed
    /// (exactly as the jti is compared as-is) — no re-normalization here.
    pub mcp_pub_b64: String,
}

/// The `mcp` claim on a scoped MCP-S3 JWT (P12). Mirrors the issuer's contract
/// in `pinning-webui/server/mcpTokens.ts` (`McpScopeClaim`). The gateway only
/// parses + enforces these in production; `Serialize` is derived solely so
/// tests can mint MCP tokens via the existing `create_test_token` helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpScopeClaim {
    /// MAJOR schema version. v1 is the only version this gateway accepts; an
    /// unknown major version is rejected (fail-closed) in [`crate::mcp_scope`].
    pub v: u32,
    /// Scope entries. v1 carries exactly one.
    #[serde(default)]
    pub scopes: Vec<McpScopeEntry>,
}

/// One scope entry inside [`McpScopeClaim`] (P12). The bucket + prefix the
/// token may touch and the permissions granted on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpScopeEntry {
    /// The single bucket this token is scoped to (e.g. `fula-ai-workspace`).
    pub bucket: String,
    /// The key-namespace prefix the token may touch (the constant `ai/`).
    pub prefix: String,
    /// Granted permission strings (subset of `read`/`write`/`list`). Unknown
    /// strings are IGNORED by the parser (forward-compat) — never a grant.
    #[serde(default)]
    pub perms: Vec<String>,
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
    validation.validate_exp = false;  // Changed to false to make expiration optional
    validation.required_spec_claims.remove("exp"); // Allow tokens without exp
    validation.leeway = config.leeway_secs;
    
    // Security audit fix #6: Set issuer validation if configured
    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }
    
    // Security audit fix #6: Set audience validation if configured.
    // L1b: when NO audience is pinned, disable aud validation entirely. In
    // jsonwebtoken 9.x `validate_aud` defaults to true, so a token that merely
    // *carries* an `aud` claim (every MCP-S3 token: aud="fula-s3-gateway") is
    // rejected with InvalidAudience even though no expected audience is set —
    // while audience-less storage tokens pass. Mirror the existing
    // `validate_exp = false` posture: signature (HMAC secret) + issuer remain
    // enforced; the audience is simply not pinned here.
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }

    decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::debug!("Token validation failed: {}", e);
            ApiError::s3(S3ErrorCode::InvalidToken, "Invalid or expired token")
        })
}

/// Convert claims to a user session
/// The jwt_token parameter is the raw JWT for forwarding to pinning service
pub fn claims_to_session(claims: Claims, jwt_token: String) -> UserSession {
    let scopes: Vec<String> = claims.scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let expires_at = claims.exp
        .and_then(|exp| DateTime::from_timestamp(exp, 0))
        .unwrap_or_else(|| Utc::now() + Duration::hours(1));

    // Security audit fix A3: Use UserSession::new() to auto-hash user ID
    UserSession::new(claims.sub, claims.name, scopes, expires_at, jwt_token)
}

/// P12 — derive the optional scoped-MCP fence from a token's claims, fail-closed.
///
/// Returns:
/// - `Ok(None)` for a normal storage token (no `token_use`, no `mcp`) — the
///   common path; the resulting session enforces nothing new.
/// - `Ok(Some(scope))` for a well-formed scoped MCP token
///   (`token_use == "mcp_s3"` AND a valid `mcp` claim).
/// - `Err(AccessDenied)` (token REFUSED) if the token looks like an MCP token
///   but is malformed — i.e. `token_use == "mcp_s3"` with an absent/invalid
///   `mcp` claim, OR (token-confusion hardening) an `mcp` claim present WITHOUT
///   `token_use == "mcp_s3"`. A malformed MCP token must never fall through to
///   broad storage access (fail-closed); an ambiguous mixed token is rejected
///   rather than silently treated as an unconstrained storage token.
///
/// Borrows `&claims` so the caller can still move `claims` into
/// `claims_to_session` afterwards.
pub fn mcp_scope_from_claims(
    claims: &Claims,
) -> Result<Option<crate::mcp_scope::McpScope>, ApiError> {
    let is_mcp = claims.token_use.as_deref() == Some("mcp_s3");

    if is_mcp {
        // Flagged as an MCP token: REQUIRE a valid mcp claim, else refuse.
        let claim = claims.mcp.as_ref().ok_or_else(|| {
            tracing::warn!("MCP token (token_use=mcp_s3) missing the `mcp` claim; refusing token");
            ApiError::s3(S3ErrorCode::AccessDenied, "malformed MCP token")
        })?;
        let scope = crate::mcp_scope::McpScope::from_claim(claim).map_err(|e| {
            tracing::warn!(reason = %e, "MCP token `mcp` claim invalid; refusing token");
            ApiError::s3(S3ErrorCode::AccessDenied, "malformed MCP token")
        })?;
        Ok(Some(scope))
    } else if claims.mcp.is_some() {
        // Token-confusion hardening (codex): an `mcp` claim WITHOUT the
        // `token_use` discriminator is ambiguous. Reject rather than treat it as
        // an unconstrained storage token.
        tracing::warn!("token carries an `mcp` claim without token_use=mcp_s3; refusing ambiguous token");
        Err(ApiError::s3(S3ErrorCode::AccessDenied, "ambiguous token"))
    } else {
        // Normal storage token — no MCP fence.
        Ok(None)
    }
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

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Admin JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    /// Subject (admin user ID)
    pub sub: String,
    /// Expiration time (required for admin tokens)
    pub exp: Option<i64>,
    /// Issued at
    pub iat: Option<i64>,
    /// Scope (must include "admin" or "*")
    #[serde(default)]
    pub scope: String,
}

impl AdminClaims {
    /// Check if this token has admin privileges
    pub fn is_valid_admin(&self) -> bool {
        self.scope
            .split_whitespace()
            .any(|s| s == "admin" || s == "*")
    }
}

/// Validate an admin JWT token and extract claims
pub fn validate_admin_token(token: &str, secret: &str) -> Result<AdminClaims, ApiError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true; // Admin tokens MUST have valid expiration
    validation.leeway = 60; // 1 minute leeway for clock skew

    let claims = decode::<AdminClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::debug!("Admin token validation failed: {}", e);
            ApiError::s3(S3ErrorCode::InvalidToken, "Invalid or expired admin token")
        })?;

    // Verify admin scope
    if !claims.is_valid_admin() {
        tracing::warn!(
            admin_id = %claims.sub,
            scope = %claims.scope,
            "Admin token missing required 'admin' scope"
        );
        return Err(ApiError::s3(
            S3ErrorCode::AccessDenied,
            "Token does not have admin privileges",
        ));
    }

    Ok(claims)
}

/// Generate an anonymous user ID for unauthenticated requests
pub fn anonymous_user_id() -> String {
    "anonymous".to_string()
}

/// Create a development/test session
pub fn dev_session() -> UserSession {
    // Security audit fix A3: Use UserSession::new() to auto-hash user ID
    // Note: dev session has empty JWT token since auth is disabled
    UserSession::new(
        "dev-user".to_string(),
        Some("Development User".to_string()),
        vec!["storage:*".to_string()],
        Utc::now() + Duration::days(365),
        String::new(), // No JWT in dev mode
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
            exp: Some((Utc::now() + Duration::hours(1)).timestamp()),
            iat: Some(Utc::now().timestamp()),
            iss: None,
            aud: None,
            scope: "storage:read storage:write".to_string(),
            name: Some("Test User".to_string()),
            jti: None,
            token_use: None,
            mcp: None,
            cnf: None,
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
            exp: Some((Utc::now() - Duration::hours(1)).timestamp()),
            iat: None,
            iss: None,
            aud: None,
            scope: String::new(),
            name: None,
            jti: None,
            token_use: None,
            mcp: None,
            cnf: None,
        };

        let token = create_test_token(&claims, secret);
        // Exp is optional by design; tokens without/with expired exp should still validate
        let result = validate_token(&token, secret);

        assert!(result.is_ok());
    }

    #[test]
    fn test_claims_to_session() {
        let claims = Claims {
            sub: "user123".to_string(),
            exp: Some((Utc::now() + Duration::hours(1)).timestamp()),
            iat: None,
            iss: None,
            aud: None,
            scope: "storage:read storage:write".to_string(),
            name: Some("Test User".to_string()),
            jti: None,
            token_use: None,
            mcp: None,
            cnf: None,
        };

        let session = claims_to_session(claims, "test-jwt-token".to_string());

        assert_eq!(session.user_id, "user123");
        assert_eq!(session.jwt_token, "test-jwt-token");
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

    // ═══════════════════════════════════════════════════════════════════════════════
    // P12 — SCOPED MCP TOKEN: end-to-end parse → validate → fail-closed → enforce
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    // These exercise the SAME chain the auth middleware runs — mint an MCP JWT,
    // `validate_token` it, derive the scope via `mcp_scope_from_claims`, build the
    // session, then `assert_mcp_scope` each scenario — so they cover the wiring,
    // not just the `mcp_scope` unit logic. The handlers each call exactly this
    // `assert_mcp_scope`, so a green here means the enforcement the handlers rely
    // on is sound.

    use crate::mcp_scope::McpAction;

    /// Mint an MCP JWT (token_use + mcp claim) the way the issuer does, via the
    /// existing test-token helper. `perms`/`bucket` are configurable so each
    /// test can shape the scope.
    fn mcp_claims(sub: &str, bucket: &str, prefix: &str, perms: &[&str]) -> Claims {
        Claims {
            sub: sub.to_string(),
            exp: Some((Utc::now() + Duration::hours(1)).timestamp()),
            iat: Some(Utc::now().timestamp()),
            // iss/aud left None here: P12's `validate_token` only enforces them
            // when a JwtValidationConfig configures an expected value (it doesn't
            // by default), and jsonwebtoken v9 rejects a token that CARRIES an
            // `aud` claim when no expected audience is set. The MCP discriminator
            // is `token_use` + `mcp`, independent of iss/aud — so omitting them
            // keeps this an honest validate→derive→enforce round-trip. (iss/aud
            // enforcement is explicitly out of P12 scope; see the report.)
            iss: None,
            aud: None,
            scope: String::new(), // MCP tokens carry NO storage scope
            name: None,
            jti: Some("test-jti-123".to_string()),
            token_use: Some("mcp_s3".to_string()),
            mcp: Some(McpScopeClaim {
                v: 1,
                scopes: vec![McpScopeEntry {
                    bucket: bucket.to_string(),
                    prefix: prefix.to_string(),
                    perms: perms.iter().map(|s| s.to_string()).collect(),
                }],
            }),
            // No connection binding by default; the L1b connection-revocation
            // tests set this to `Some(...)` after calling the helper.
            cnf: None,
        }
    }

    /// Run the full middleware chain (validate → derive scope → build session)
    /// for a freshly-minted token and return the resulting session.
    fn session_from_claims(claims: &Claims, secret: &str) -> UserSession {
        let token = create_test_token(claims, secret);
        let validated = validate_token(&token, secret).expect("token validates");
        let scope = mcp_scope_from_claims(&validated).expect("scope derives");
        let mut session = claims_to_session(validated, token);
        session.mcp_scope = scope;
        session
    }

    #[test]
    fn mcp_token_in_scope_ops_pass() {
        let secret = "test-secret";
        let claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read", "write", "list"]);
        let session = session_from_claims(&claims, secret);

        // The session is recognized as MCP-scoped.
        assert!(session.mcp_scope.is_some(), "MCP token must carry a scope");

        // In-scope object read/write + bucket list/create all pass.
        assert!(session.assert_mcp_scope("fula-ai-workspace", Some("ai/notes/x.txt"), McpAction::Read).is_ok());
        assert!(session.assert_mcp_scope("fula-ai-workspace", Some("ai/notes/x.txt"), McpAction::Write).is_ok());
        assert!(session.assert_mcp_scope("fula-ai-workspace", None, McpAction::List).is_ok());
        assert!(session.assert_mcp_scope("fula-ai-workspace", None, McpAction::Write).is_ok());
    }

    #[test]
    fn mcp_token_other_bucket_is_access_denied() {
        let secret = "test-secret";
        let claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read", "write", "list"]);
        let session = session_from_claims(&claims, secret);

        let err = session
            .assert_mcp_scope("victim-bucket", Some("ai/x"), McpAction::Read)
            .expect_err("other bucket must be denied");
        // Surfaces as an opaque S3 AccessDenied (403).
        assert!(matches!(err.error_code(), S3ErrorCode::AccessDenied));
    }

    #[test]
    fn mcp_token_aimage_boundary_key_is_access_denied() {
        // The segment-boundary regression: `aimage/...` must NOT be inside `ai/`.
        let secret = "test-secret";
        let claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read", "write", "list"]);
        let session = session_from_claims(&claims, secret);

        assert!(session
            .assert_mcp_scope("fula-ai-workspace", Some("aimage/secret.txt"), McpAction::Read)
            .is_err());
        assert!(session
            .assert_mcp_scope("fula-ai-workspace", Some("other/key"), McpAction::Write)
            .is_err());
    }

    #[test]
    fn mcp_token_missing_perm_is_access_denied() {
        // A read-only MCP token may read but not write, even in-scope.
        let secret = "test-secret";
        let claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read"]);
        let session = session_from_claims(&claims, secret);

        assert!(session.assert_mcp_scope("fula-ai-workspace", Some("ai/x"), McpAction::Read).is_ok());
        assert!(session.assert_mcp_scope("fula-ai-workspace", Some("ai/x"), McpAction::Write).is_err());
        // ...and cannot list (no list perm).
        assert!(session.assert_mcp_scope("fula-ai-workspace", None, McpAction::List).is_err());
    }

    #[test]
    fn mcp_capability_gate_derives_from_perms() {
        // The CAPABILITY gate (can_read/can_write) — which every handler runs
        // BEFORE assert_mcp_scope — must derive from the MCP perms, since an MCP
        // token carries no storage `scope`. This is the regression for the
        // empty-scope defect (without it, can_read/can_write are false and every
        // MCP op is rejected before the scope check).
        let secret = "test-secret";

        // Full perms: can_read AND can_write.
        let full = session_from_claims(
            &mcp_claims("u", "fula-ai-workspace", "ai/", &["read", "write", "list"]),
            secret,
        );
        assert!(full.can_read() && full.can_write());

        // Read-only: can_read, NOT can_write.
        let ro = session_from_claims(&mcp_claims("u", "fula-ai-workspace", "ai/", &["read"]), secret);
        assert!(ro.can_read());
        assert!(!ro.can_write());

        // List-only: can_read TRUE (so it passes the can_read gate that
        // list_objects runs) but NOT can_write — and assert(Read) on an actual
        // object GET still denies it (assert is the authoritative fence).
        let list_only = session_from_claims(&mcp_claims("u", "fula-ai-workspace", "ai/", &["list"]), secret);
        assert!(list_only.can_read(), "list perm grants coarse read capability");
        assert!(!list_only.can_write());
        assert!(list_only.assert_mcp_scope("fula-ai-workspace", None, McpAction::List).is_ok());
        assert!(
            list_only.assert_mcp_scope("fula-ai-workspace", Some("ai/x"), McpAction::Read).is_err(),
            "list-only must still be denied an actual object GET by assert"
        );

        // An MCP session is never admin (empty storage scope).
        assert!(!full.is_admin());
    }

    #[test]
    fn normal_storage_token_is_unaffected_by_mcp_enforcement() {
        // REGRESSION: a normal storage token (no token_use, no mcp) gets
        // mcp_scope == None, so every assert_mcp_scope is a no-op Ok — it can
        // touch any bucket/key/action exactly as before P12.
        let secret = "test-secret";
        let claims = Claims {
            sub: "storage-user".to_string(),
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            scope: "storage:read storage:write".to_string(),
            name: None,
            jti: None,
            token_use: None,
            mcp: None,
            cnf: None,
        };
        let session = session_from_claims(&claims, secret);

        assert!(session.mcp_scope.is_none(), "storage token must NOT be MCP-scoped");
        assert!(session.can_read() && session.can_write());
        // Any bucket / any key / any action — all pass (no MCP fence).
        assert!(session.assert_mcp_scope("any-bucket", Some("anything/at/all"), McpAction::Write).is_ok());
        assert!(session.assert_mcp_scope("another", None, McpAction::List).is_ok());
        assert!(session.assert_mcp_scope("aimage-bucket", Some("aimage/x"), McpAction::Read).is_ok());
    }

    #[test]
    fn mcp_flagged_token_without_mcp_claim_is_refused() {
        // FAIL-CLOSED: token_use=mcp_s3 but NO mcp claim ⇒ the whole token is
        // refused at mcp_scope_from_claims (must NOT fall through to broad access).
        let secret = "test-secret";
        let mut claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read"]);
        claims.mcp = None; // strip the scope claim but keep token_use
        let token = create_test_token(&claims, secret);
        let validated = validate_token(&token, secret).unwrap();
        assert!(
            mcp_scope_from_claims(&validated).is_err(),
            "an MCP-flagged token with no mcp claim must be refused"
        );
    }

    #[test]
    fn mcp_token_with_unsupported_version_is_refused() {
        // FAIL-CLOSED: mcp.v != 1 ⇒ token refused (never treated as unconstrained).
        let secret = "test-secret";
        let mut claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read"]);
        if let Some(ref mut m) = claims.mcp {
            m.v = 2;
        }
        let token = create_test_token(&claims, secret);
        let validated = validate_token(&token, secret).unwrap();
        assert!(
            mcp_scope_from_claims(&validated).is_err(),
            "mcp.v=2 must be refused by the v1 gateway"
        );
    }

    #[test]
    fn ambiguous_mcp_claim_without_token_use_is_refused() {
        // TOKEN-CONFUSION HARDENING: an mcp claim present WITHOUT
        // token_use=mcp_s3 is ambiguous ⇒ refused (not silently treated as a
        // storage token).
        let secret = "test-secret";
        let mut claims = mcp_claims("user-sub", "fula-ai-workspace", "ai/", &["read"]);
        claims.token_use = None; // mcp present, but no discriminator
        let token = create_test_token(&claims, secret);
        let validated = validate_token(&token, secret).unwrap();
        assert!(
            mcp_scope_from_claims(&validated).is_err(),
            "an mcp claim without token_use=mcp_s3 must be refused as ambiguous"
        );
    }
}
