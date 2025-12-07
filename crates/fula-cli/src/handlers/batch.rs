//! Batch operation handlers (DeleteObjects)

use crate::{AppState, ApiError, S3ErrorCode};
use crate::state::UserSession;
use crate::xml;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::sync::Arc;

/// POST /{bucket}?delete - Batch delete objects
pub async fn delete_objects(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<UserSession>,
    Path(bucket_name): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !session.can_write() {
        return Err(ApiError::s3(S3ErrorCode::AccessDenied, "Write access required"));
    }

    let mut bucket = state.bucket_manager.open_bucket(&bucket_name).await?;
    
    // Parse the delete request XML
    let body_str = String::from_utf8_lossy(&body);
    let (keys, quiet) = parse_delete_request(&body_str)?;
    
    if keys.len() > 1000 {
        return Err(ApiError::s3(
            S3ErrorCode::InvalidArgument,
            "Maximum 1000 objects per delete request",
        ));
    }

    let mut deleted = Vec::new();
    let mut errors: Vec<(String, &str, &str)> = Vec::new();

    for key in keys {
        match bucket.delete_object(&key).await {
            Ok(Some(_)) => {
                deleted.push(key);
            }
            Ok(None) => {
                // Object didn't exist - still count as deleted per S3 semantics
                deleted.push(key);
            }
            Err(e) => {
                errors.push((key, "InternalError", "Failed to delete object"));
                tracing::error!("Failed to delete object: {}", e);
            }
        }
    }

    bucket.flush().await?;

    // Build response
    let xml_response = if quiet && errors.is_empty() {
        // Quiet mode - only return errors
        r#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>"#.to_string()
    } else {
        xml::delete_result(&deleted, &errors)
    };

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/xml")],
        xml_response,
    ).into_response())
}

/// Parse delete request XML
fn parse_delete_request(xml: &str) -> Result<(Vec<String>, bool), ApiError> {
    let mut keys = Vec::new();
    
    // Check for quiet mode
    let quiet = xml.contains("<Quiet>true</Quiet>") || xml.contains("<Quiet>1</Quiet>");
    
    // Extract all <Key> elements within <Object> elements
    let mut pos = 0;
    while let Some(obj_start) = xml[pos..].find("<Object>") {
        let obj_start = pos + obj_start;
        if let Some(obj_end) = xml[obj_start..].find("</Object>") {
            let obj_xml = &xml[obj_start..obj_start + obj_end + 9];
            
            if let Some(key) = extract_xml_element(obj_xml, "Key") {
                keys.push(key);
            }
            
            pos = obj_start + obj_end + 9;
        } else {
            break;
        }
    }
    
    if keys.is_empty() {
        return Err(ApiError::s3(
            S3ErrorCode::MalformedXML,
            "No objects specified for deletion",
        ));
    }
    
    Ok((keys, quiet))
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
    fn test_parse_delete_request() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
    <Quiet>false</Quiet>
    <Object>
        <Key>file1.txt</Key>
    </Object>
    <Object>
        <Key>file2.txt</Key>
    </Object>
</Delete>"#;

        let (keys, quiet) = parse_delete_request(xml).unwrap();
        assert_eq!(keys, vec!["file1.txt", "file2.txt"]);
        assert!(!quiet);
    }

    #[test]
    fn test_parse_delete_request_quiet() {
        let xml = r#"<Delete><Quiet>true</Quiet><Object><Key>test.txt</Key></Object></Delete>"#;

        let (keys, quiet) = parse_delete_request(xml).unwrap();
        assert_eq!(keys, vec!["test.txt"]);
        assert!(quiet);
    }
}
