//! Authentication and authorization

use crate::{ApiError, S3ErrorCode};
use crate::state::UserSession;
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

/// Validate a JWT token and extract claims
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    
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

    UserSession {
        user_id: claims.sub,
        display_name: claims.name,
        scopes,
        expires_at: DateTime::from_timestamp(claims.exp, 0)
            .unwrap_or_else(|| Utc::now() + Duration::hours(1)),
    }
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
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
    UserSession {
        user_id: "dev-user".to_string(),
        display_name: Some("Development User".to_string()),
        scopes: vec!["storage:*".to_string()],
        expires_at: Utc::now() + Duration::days(365),
    }
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
}
