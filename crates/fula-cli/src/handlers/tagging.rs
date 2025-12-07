//! Object tagging handlers

use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::UserSession;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::sync::Arc;

/// GET /{bucket}/{key}?tagging - Get object tags
pub async fn get_object_tagging(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if !session.can_read() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Read access required"));
    }

    let bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
    let metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    // Build XML response
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <TagSet>"#);

    for (k, v) in &metadata.tags {
        xml.push_str(&format!(
            r#"
        <Tag>
            <Key>{}</Key>
            <Value>{}</Value>
        </Tag>"#,
            escape_xml(k),
            escape_xml(v)
        ));
    }

    xml.push_str(r#"
    </TagSet>
</Tagging>"#);

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml,
    ).into_response())
}

/// PUT /{bucket}/{key}?tagging - Set object tags
pub async fn put_object_tagging(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let mut bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
    let mut metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    // Parse tags from XML body
    let body_str = String::from_utf8_lossy(&body);
    let tags = parse_tagging_xml(&body_str)?;
    
    // Update tags
    metadata.tags = tags;
    
    bucket.put_object(key, metadata).await?;
    bucket.flush().await?;

    Ok(StatusCode::OK.into_response())
}

/// DELETE /{bucket}/{key}?tagging - Delete object tags
pub async fn delete_object_tagging(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path((bucket_name, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let mut bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
    let mut metadata = bucket.get_object(&key).await?
        .ok_or_else(|| ApiError::s3_with_resource(
            S3ErrorCode::NoSuchKey,
            "Object not found",
            format!("{}/{}", bucket_name, key),
        ))?;

    // Clear tags
    metadata.tags.clear();
    
    bucket.put_object(key, metadata).await?;
    bucket.flush().await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Parse tagging XML
fn parse_tagging_xml(xml: &str) -> Result<std::collections::HashMap<String, String>, ApiError> {
    let mut tags = std::collections::HashMap::new();
    
    // Simple XML parsing for <Tag><Key>...</Key><Value>...</Value></Tag>
    let mut pos = 0;
    while let Some(tag_start) = xml[pos..].find("<Tag>") {
        let tag_start = pos + tag_start;
        if let Some(tag_end) = xml[tag_start..].find("</Tag>") {
            let tag_xml = &xml[tag_start..tag_start + tag_end + 6];
            
            let key = extract_xml_element(tag_xml, "Key");
            let value = extract_xml_element(tag_xml, "Value");
            
            if let (Some(k), Some(v)) = (key, value) {
                if tags.len() >= 10 {
                    return Err(ApiError::s3(
                        S3ErrorCode::InvalidArgument,
                        "Maximum 10 tags allowed",
                    ));
                }
                tags.insert(k, v);
            }
            
            pos = tag_start + tag_end + 6;
        } else {
            break;
        }
    }
    
    Ok(tags)
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

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
