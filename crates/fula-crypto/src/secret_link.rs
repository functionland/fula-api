//! Secret Link URL Patterns (Peergos-inspired)
//!
//! This module implements secure share links where **all sensitive key material
//! is kept in the URL fragment (`#...`)**, which is never sent to the server.
//!
//! ## Design
//!
//! A secret link has the format:
//! ```text
//! https://gateway.example/fula/share/<opaque-id>#<base64url-encoded-payload>
//! ```
//!
//! - **Server sees**: `/fula/share/<opaque-id>` only (for logging, rate limits, revocation)
//! - **Client sees**: Fragment containing the encrypted ShareToken or capability
//!
//! ## Security Properties
//!
//! - **Fragment privacy**: URL fragments are never sent to servers in HTTP requests
//! - **Key isolation**: Gateway cannot decrypt shared content even if compromised
//! - **Revocation support**: Opaque ID can be checked against a revocation list
//! - **Forward compatibility**: Versioned payload format allows upgrades
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fula_crypto::{SecretLink, ShareToken};
//!
//! // Create a secret link from a share token
//! let link = SecretLink::from_token(&token, "https://gateway.example")?;
//! let url = link.to_url();
//! // => "https://gateway.example/fula/share/abc123#eyJ2ZXJzaW9u..."
//!
//! // Parse a secret link URL
//! let parsed = SecretLink::parse(&url)?;
//! let token = parsed.extract_token()?;
//! ```

use crate::{CryptoError, Result, sharing::ShareToken};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Default path prefix for share links
pub const SHARE_PATH_PREFIX: &str = "/fula/share/";

/// Current version of the secret link format
pub const SECRET_LINK_VERSION: u8 = 1;

/// A secret link that contains share credentials in the URL fragment
///
/// The fragment is base64url-encoded and contains the full ShareToken,
/// ensuring that gateways and servers never see the key material.
#[derive(Clone, Debug)]
pub struct SecretLink {
    /// The base URL of the gateway (e.g., "https://gateway.example")
    pub gateway_url: String,
    /// Opaque identifier visible to the server (for logging, rate limits, revocation)
    pub opaque_id: String,
    /// The secret payload (kept in fragment, never sent to server)
    pub payload: SecretLinkPayload,
}

/// The payload stored in the URL fragment
///
/// This is base64url-encoded and contains all sensitive key material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretLinkPayload {
    /// Version of the payload format
    pub version: u8,
    /// The share token containing the wrapped DEK and permissions
    pub token: ShareToken,
    /// Optional human-readable label for the share
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional metadata (e.g., sharer identity hint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

impl SecretLink {
    /// Create a new secret link from a share token
    ///
    /// # Arguments
    /// * `token` - The ShareToken to embed in the link
    /// * `gateway_url` - The base URL of the gateway (e.g., "https://gateway.example")
    ///
    /// # Returns
    /// A SecretLink that can be converted to a URL string
    pub fn from_token(token: &ShareToken, gateway_url: &str) -> Result<Self> {
        Self::from_token_with_label(token, gateway_url, None)
    }

    /// Create a new secret link with an optional label
    pub fn from_token_with_label(
        token: &ShareToken,
        gateway_url: &str,
        label: Option<String>,
    ) -> Result<Self> {
        // Use the token's ID as the opaque ID (visible to server)
        let opaque_id = token.id.clone();

        let payload = SecretLinkPayload {
            version: SECRET_LINK_VERSION,
            token: token.clone(),
            label,
            metadata: None,
        };

        Ok(Self {
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            opaque_id,
            payload,
        })
    }

    /// Create a secret link with custom metadata
    pub fn from_token_with_metadata(
        token: &ShareToken,
        gateway_url: &str,
        label: Option<String>,
        metadata: Option<String>,
    ) -> Result<Self> {
        let opaque_id = token.id.clone();

        let payload = SecretLinkPayload {
            version: SECRET_LINK_VERSION,
            token: token.clone(),
            label,
            metadata,
        };

        Ok(Self {
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            opaque_id,
            payload,
        })
    }

    /// Convert the secret link to a full URL string
    ///
    /// The returned URL has the format:
    /// `<gateway_url>/fula/share/<opaque_id>#<base64url_payload>`
    pub fn to_url(&self) -> Result<String> {
        let encoded_payload = self.encode_payload()?;
        Ok(format!(
            "{}{}{}#{}",
            self.gateway_url, SHARE_PATH_PREFIX, self.opaque_id, encoded_payload
        ))
    }

    /// Encode the payload as base64url
    fn encode_payload(&self) -> Result<String> {
        let json = serde_json::to_vec(&self.payload)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }

    /// Parse a secret link from a URL string
    ///
    /// # Arguments
    /// * `url` - The full URL including fragment
    ///
    /// # Returns
    /// A SecretLink if parsing succeeds
    pub fn parse(url: &str) -> Result<Self> {
        // Split on '#' to get base URL and fragment
        let parts: Vec<&str> = url.splitn(2, '#').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidFormat(
                "Secret link must contain a fragment (#)".to_string(),
            ));
        }

        let base_url = parts[0];
        let fragment = parts[1];

        // Parse the base URL to extract gateway and opaque ID
        let (gateway_url, opaque_id) = Self::parse_base_url(base_url)?;

        // Decode the fragment payload
        let payload = Self::decode_payload(fragment)?;

        Ok(Self {
            gateway_url,
            opaque_id,
            payload,
        })
    }

    /// Parse the base URL to extract gateway URL and opaque ID
    fn parse_base_url(base_url: &str) -> Result<(String, String)> {
        // Find the share path prefix
        if let Some(idx) = base_url.find(SHARE_PATH_PREFIX) {
            let gateway_url = base_url[..idx].to_string();
            let opaque_id = base_url[idx + SHARE_PATH_PREFIX.len()..].to_string();

            if opaque_id.is_empty() {
                return Err(CryptoError::InvalidFormat(
                    "Missing opaque ID in secret link".to_string(),
                ));
            }

            Ok((gateway_url, opaque_id))
        } else {
            Err(CryptoError::InvalidFormat(format!(
                "Secret link must contain path prefix: {}",
                SHARE_PATH_PREFIX
            )))
        }
    }

    /// Decode the payload from base64url
    fn decode_payload(fragment: &str) -> Result<SecretLinkPayload> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(fragment)
            .map_err(|e| CryptoError::InvalidFormat(format!("Invalid base64url: {}", e)))?;

        serde_json::from_slice(&bytes)
            .map_err(|e| CryptoError::Serialization(format!("Invalid payload JSON: {}", e)))
    }

    /// Extract the ShareToken from this secret link
    pub fn extract_token(&self) -> &ShareToken {
        &self.payload.token
    }

    /// Get the opaque ID (visible to server)
    pub fn opaque_id(&self) -> &str {
        &self.opaque_id
    }

    /// Get the optional label
    pub fn label(&self) -> Option<&str> {
        self.payload.label.as_deref()
    }

    /// Get the optional metadata
    pub fn metadata(&self) -> Option<&str> {
        self.payload.metadata.as_deref()
    }

    /// Check if the embedded token is expired
    pub fn is_expired(&self) -> bool {
        self.payload.token.is_expired()
    }

    /// Check if the embedded token is valid for a given path
    pub fn is_valid_for_path(&self, path: &str) -> bool {
        self.payload.token.is_valid_for_path(path)
    }

    /// Get the path scope from the embedded token
    pub fn path_scope(&self) -> &str {
        &self.payload.token.path_scope
    }

    /// Get the permissions from the embedded token
    pub fn can_read(&self) -> bool {
        self.payload.token.can_read()
    }

    pub fn can_write(&self) -> bool {
        self.payload.token.can_write()
    }

    pub fn can_delete(&self) -> bool {
        self.payload.token.can_delete()
    }
}

/// Builder for creating secret links with fluent API
pub struct SecretLinkBuilder<'a> {
    token: &'a ShareToken,
    gateway_url: String,
    label: Option<String>,
    metadata: Option<String>,
}

impl<'a> SecretLinkBuilder<'a> {
    /// Create a new builder
    pub fn new(token: &'a ShareToken, gateway_url: &str) -> Self {
        Self {
            token,
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            label: None,
            metadata: None,
        }
    }

    /// Set a human-readable label
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set optional metadata
    pub fn metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }

    /// Build the secret link
    pub fn build(self) -> Result<SecretLink> {
        SecretLink::from_token_with_metadata(
            self.token,
            &self.gateway_url,
            self.label,
            self.metadata,
        )
    }
}

/// Validate that a URL is a valid secret link without fully parsing
///
/// This is useful for quick checks before attempting full parsing.
pub fn is_valid_secret_link_url(url: &str) -> bool {
    url.contains(SHARE_PATH_PREFIX) && url.contains('#')
}

/// Extract just the opaque ID from a secret link URL
///
/// This is useful for server-side operations that don't need the full token.
pub fn extract_opaque_id(url: &str) -> Option<String> {
    // Split on '#' first
    let base_url = url.split('#').next()?;

    // Find the share path prefix
    let idx = base_url.find(SHARE_PATH_PREFIX)?;
    let opaque_id = &base_url[idx + SHARE_PATH_PREFIX.len()..];

    if opaque_id.is_empty() {
        None
    } else {
        Some(opaque_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DekKey, KekKeyPair};
    use crate::sharing::ShareBuilder;

    fn create_test_token() -> ShareToken {
        let owner = KekKeyPair::generate();
        let recipient = KekKeyPair::generate();
        let dek = DekKey::generate();

        ShareBuilder::new(&owner, recipient.public_key(), &dek)
            .path_scope("/photos/vacation/")
            .expires_in(3600)
            .read_only()
            .build()
            .unwrap()
    }

    #[test]
    fn test_secret_link_creation() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();

        assert_eq!(link.gateway_url, "https://gateway.example");
        assert_eq!(link.opaque_id, token.id);
        assert_eq!(link.payload.version, SECRET_LINK_VERSION);
    }

    #[test]
    fn test_secret_link_to_url() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();
        let url = link.to_url().unwrap();

        // URL should have the correct format
        assert!(url.starts_with("https://gateway.example/fula/share/"));
        assert!(url.contains('#'));

        // Fragment should be base64url encoded
        let fragment = url.split('#').nth(1).unwrap();
        assert!(!fragment.is_empty());
        // Base64url should not contain + or / (it uses - and _)
        assert!(!fragment.contains('+'));
        assert!(!fragment.contains('/'));
    }

    #[test]
    fn test_secret_link_roundtrip() {
        let token = create_test_token();
        let original_link = SecretLink::from_token(&token, "https://gateway.example").unwrap();
        let url = original_link.to_url().unwrap();

        // Parse the URL
        let parsed_link = SecretLink::parse(&url).unwrap();

        // Verify all fields match
        assert_eq!(parsed_link.gateway_url, original_link.gateway_url);
        assert_eq!(parsed_link.opaque_id, original_link.opaque_id);
        assert_eq!(parsed_link.payload.version, original_link.payload.version);
        assert_eq!(
            parsed_link.payload.token.id,
            original_link.payload.token.id
        );
        assert_eq!(
            parsed_link.payload.token.path_scope,
            original_link.payload.token.path_scope
        );
    }

    #[test]
    fn test_secret_link_with_label() {
        let token = create_test_token();
        let link = SecretLinkBuilder::new(&token, "https://gateway.example")
            .label("Vacation Photos 2024")
            .build()
            .unwrap();

        assert_eq!(link.label(), Some("Vacation Photos 2024"));

        // Roundtrip preserves label
        let url = link.to_url().unwrap();
        let parsed = SecretLink::parse(&url).unwrap();
        assert_eq!(parsed.label(), Some("Vacation Photos 2024"));
    }

    #[test]
    fn test_secret_link_with_metadata() {
        let token = create_test_token();
        let link = SecretLinkBuilder::new(&token, "https://gateway.example")
            .label("My Photos")
            .metadata("Shared by Alice")
            .build()
            .unwrap();

        assert_eq!(link.label(), Some("My Photos"));
        assert_eq!(link.metadata(), Some("Shared by Alice"));

        // Roundtrip preserves metadata
        let url = link.to_url().unwrap();
        let parsed = SecretLink::parse(&url).unwrap();
        assert_eq!(parsed.metadata(), Some("Shared by Alice"));
    }

    #[test]
    fn test_extract_opaque_id() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();
        let url = link.to_url().unwrap();

        let opaque_id = extract_opaque_id(&url);
        assert_eq!(opaque_id, Some(token.id));
    }

    #[test]
    fn test_is_valid_secret_link_url() {
        assert!(is_valid_secret_link_url(
            "https://gateway.example/fula/share/abc123#eyJ2ZXJzaW9u"
        ));
        assert!(!is_valid_secret_link_url(
            "https://gateway.example/fula/share/abc123"
        )); // No fragment
        assert!(!is_valid_secret_link_url(
            "https://gateway.example/other/path#abc"
        )); // Wrong path
    }

    #[test]
    fn test_parse_invalid_url_no_fragment() {
        let result = SecretLink::parse("https://gateway.example/fula/share/abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_url_wrong_path() {
        let result = SecretLink::parse("https://gateway.example/other/path/abc123#eyJhIjoxfQ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_payload() {
        let result = SecretLink::parse("https://gateway.example/fula/share/abc123#not-valid-base64!");
        assert!(result.is_err());
    }

    #[test]
    fn test_gateway_url_trailing_slash() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example/").unwrap();
        let url = link.to_url().unwrap();

        // Should not have double slashes
        assert!(!url.contains("//fula"));
        assert!(url.starts_with("https://gateway.example/fula/share/"));
    }

    #[test]
    fn test_secret_link_permissions() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();

        // Token was created with read_only
        assert!(link.can_read());
        assert!(!link.can_write());
        assert!(!link.can_delete());
    }

    #[test]
    fn test_secret_link_path_validation() {
        let token = create_test_token();
        let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();

        assert!(link.is_valid_for_path("/photos/vacation/beach.jpg"));
        assert!(link.is_valid_for_path("/photos/vacation/subfolder/photo.jpg"));
        assert!(!link.is_valid_for_path("/documents/secret.pdf"));
    }

    #[test]
    fn test_fragment_never_contains_sensitive_chars() {
        // Create multiple tokens and verify fragments are URL-safe
        for _ in 0..10 {
            let token = create_test_token();
            let link = SecretLink::from_token(&token, "https://gateway.example").unwrap();
            let url = link.to_url().unwrap();
            let fragment = url.split('#').nth(1).unwrap();

            // URL-safe base64 should not contain these characters
            assert!(!fragment.contains('+'), "Fragment should not contain '+'");
            assert!(!fragment.contains('/'), "Fragment should not contain '/'");
            assert!(!fragment.contains('='), "Fragment should not contain padding '='");
        }
    }
}
