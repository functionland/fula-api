//! Main client implementation

use crate::{
    Config, ClientError, Result,
    types::*,
};
use bytes::Bytes;
use reqwest::{Client, Response, header};
use std::collections::HashMap;
use tracing::{debug, instrument};

/// Fula storage client
pub struct FulaClient {
    config: Config,
    http: Client,
}

impl FulaClient {
    /// Create a new client with the given configuration
    pub fn new(config: Config) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            config.user_agent.parse().unwrap(),
        );

        let http = Client::builder()
            .timeout(config.timeout)
            .default_headers(headers)
            .build()
            .map_err(ClientError::Http)?;

        Ok(Self { config, http })
    }

    /// Create with default configuration
    pub fn default_local() -> Result<Self> {
        Self::new(Config::default())
    }

    /// Create with endpoint URL
    pub fn with_endpoint(endpoint: &str) -> Result<Self> {
        Self::new(Config::new(endpoint))
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    // ==================== Bucket Operations ====================

    /// List all buckets
    #[instrument(skip(self))]
    pub async fn list_buckets(&self) -> Result<ListBucketsResult> {
        let response = self.request("GET", "/", None, None, None).await?;
        let text = response.text().await?;
        parse_list_buckets_response(&text)
    }

    /// Create a bucket
    #[instrument(skip(self))]
    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        let path = format!("/{}", bucket);
        self.request("PUT", &path, None, None, None).await?;
        Ok(())
    }

    /// Delete a bucket
    #[instrument(skip(self))]
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        let path = format!("/{}", bucket);
        self.request("DELETE", &path, None, None, None).await?;
        Ok(())
    }

    /// Check if a bucket exists
    #[instrument(skip(self))]
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        let path = format!("/{}", bucket);
        match self.request("HEAD", &path, None, None, None).await {
            Ok(_) => Ok(true),
            Err(ClientError::S3Error { code, .. }) if code == "NoSuchBucket" => Ok(false),
            Err(e) => Err(e),
        }
    }

    // ==================== Object Operations ====================

    /// List objects in a bucket
    #[instrument(skip(self))]
    pub async fn list_objects(
        &self,
        bucket: &str,
        options: Option<ListObjectsOptions>,
    ) -> Result<ListObjectsResult> {
        let opts = options.unwrap_or_default();
        let mut query = vec![("list-type", "2".to_string())];
        
        if let Some(prefix) = &opts.prefix {
            query.push(("prefix", prefix.clone()));
        }
        if let Some(delimiter) = &opts.delimiter {
            query.push(("delimiter", delimiter.clone()));
        }
        if let Some(max_keys) = opts.max_keys {
            query.push(("max-keys", max_keys.to_string()));
        }
        if let Some(token) = &opts.continuation_token {
            query.push(("continuation-token", token.clone()));
        }
        if let Some(start_after) = &opts.start_after {
            query.push(("start-after", start_after.clone()));
        }

        let path = format!("/{}", bucket);
        let response = self.request("GET", &path, Some(&query), None, None).await?;
        let text = response.text().await?;
        parse_list_objects_response(&text, bucket)
    }

    /// Put an object
    #[instrument(skip(self, data))]
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
    ) -> Result<PutObjectResult> {
        self.put_object_with_metadata(bucket, key, data, None).await
    }

    /// Put an object with metadata
    #[instrument(skip(self, data))]
    pub async fn put_object_with_metadata(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        metadata: Option<ObjectMetadata>,
    ) -> Result<PutObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let data = data.into();

        let mut headers = HashMap::new();
        if let Some(meta) = metadata {
            if let Some(ct) = meta.content_type {
                headers.insert("Content-Type".to_string(), ct);
            }
            for (k, v) in meta.user_metadata {
                headers.insert(format!("x-amz-meta-{}", k), v);
            }
        }

        let response = self.request("PUT", &path, None, Some(headers), Some(data)).await?;
        
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        Ok(PutObjectResult {
            etag,
            version_id: None,
        })
    }

    /// Get an object
    #[instrument(skip(self))]
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes> {
        let result = self.get_object_with_metadata(bucket, key).await?;
        Ok(result.data)
    }

    /// Get an object with metadata
    #[instrument(skip(self))]
    pub async fn get_object_with_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<GetObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let response = self.request("GET", &path, None, None, None).await?;
        
        let headers = response.headers();
        let etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        
        let content_type = headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        
        let content_length = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut metadata = HashMap::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if let Ok(v) = value.to_str() {
                    metadata.insert(key.to_string(), v.to_string());
                }
            }
        }

        let data = response.bytes().await?;

        Ok(GetObjectResult {
            data,
            etag,
            content_type,
            content_length,
            last_modified: None,
            metadata,
        })
    }

    /// Check if an object exists
    #[instrument(skip(self))]
    pub async fn object_exists(&self, bucket: &str, key: &str) -> Result<bool> {
        match self.head_object(bucket, key).await {
            Ok(_) => Ok(true),
            Err(ClientError::S3Error { code, .. }) if code == "NoSuchKey" => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Head an object (get metadata without content)
    #[instrument(skip(self))]
    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectResult> {
        let path = format!("/{}/{}", bucket, key);
        let response = self.request("HEAD", &path, None, None, None).await?;
        
        let headers = response.headers();
        let etag = headers
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();
        
        let content_type = headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        
        let content_length = headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut metadata = HashMap::new();
        for (name, value) in headers.iter() {
            if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
                if let Ok(v) = value.to_str() {
                    metadata.insert(key.to_string(), v.to_string());
                }
            }
        }

        Ok(HeadObjectResult {
            etag,
            content_type,
            content_length,
            last_modified: None,
            metadata,
        })
    }

    /// Delete an object
    #[instrument(skip(self))]
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let path = format!("/{}/{}", bucket, key);
        self.request("DELETE", &path, None, None, None).await?;
        Ok(())
    }

    /// Copy an object
    #[instrument(skip(self))]
    pub async fn copy_object(
        &self,
        source_bucket: &str,
        source_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<CopyObjectResult> {
        let path = format!("/{}/{}", dest_bucket, dest_key);
        let copy_source = format!("/{}/{}", source_bucket, source_key);
        
        let mut headers = HashMap::new();
        headers.insert("x-amz-copy-source".to_string(), copy_source);

        let response = self.request("PUT", &path, None, Some(headers), None).await?;
        let text = response.text().await?;
        parse_copy_object_response(&text)
    }

    // ==================== Helper Methods ====================

    async fn request(
        &self,
        method: &str,
        path: &str,
        query: Option<&[(&str, String)]>,
        headers: Option<HashMap<String, String>>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let url = format!("{}{}", self.config.endpoint, path);
        
        let mut req = match method {
            "GET" => self.http.get(&url),
            "PUT" => self.http.put(&url),
            "POST" => self.http.post(&url),
            "DELETE" => self.http.delete(&url),
            "HEAD" => self.http.head(&url),
            _ => return Err(ClientError::Config(format!("Unknown method: {}", method))),
        };

        // Add query parameters
        if let Some(q) = query {
            req = req.query(q);
        }

        // Add authorization
        if let Some(token) = &self.config.access_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        // Add custom headers
        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                req = req.header(&k, v);
            }
        }

        // Add body
        if let Some(data) = body {
            req = req.body(data);
        }

        debug!("Sending {} request to {}", method, url);
        let response = req.send().await?;

        // Check for errors
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(ClientError::from_s3_xml(&text, status.as_u16()));
        }

        Ok(response)
    }
}

// ==================== Response Parsers ====================

fn parse_list_buckets_response(xml: &str) -> Result<ListBucketsResult> {
    // Simple XML parsing
    let owner_id = extract_xml_value(xml, "ID").unwrap_or_default();
    let owner_display_name = extract_xml_value(xml, "DisplayName").unwrap_or_default();
    
    let mut buckets = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<Bucket>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</Bucket>") {
            let bucket_xml = &xml[start..start + end + 9];
            if let (Some(name), Some(date)) = (
                extract_xml_value(bucket_xml, "Name"),
                extract_xml_value(bucket_xml, "CreationDate"),
            ) {
                buckets.push(Bucket {
                    name,
                    creation_date: chrono::DateTime::parse_from_rfc3339(&date)
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                });
            }
            pos = start + end + 9;
        } else {
            break;
        }
    }

    Ok(ListBucketsResult {
        owner_id,
        owner_display_name,
        buckets,
    })
}

fn parse_list_objects_response(xml: &str, bucket: &str) -> Result<ListObjectsResult> {
    let prefix = extract_xml_value(xml, "Prefix").unwrap_or_default();
    let is_truncated = extract_xml_value(xml, "IsTruncated")
        .map(|s| s == "true")
        .unwrap_or(false);
    let next_token = extract_xml_value(xml, "NextContinuationToken");

    let mut objects = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<Contents>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</Contents>") {
            let obj_xml = &xml[start..start + end + 11];
            if let Some(key) = extract_xml_value(obj_xml, "Key") {
                objects.push(Object {
                    key,
                    last_modified: extract_xml_value(obj_xml, "LastModified")
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_else(chrono::Utc::now),
                    etag: extract_xml_value(obj_xml, "ETag")
                        .map(|s| s.trim_matches('"').to_string())
                        .unwrap_or_default(),
                    size: extract_xml_value(obj_xml, "Size")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    storage_class: extract_xml_value(obj_xml, "StorageClass")
                        .unwrap_or_else(|| "STANDARD".to_string()),
                });
            }
            pos = start + end + 11;
        } else {
            break;
        }
    }

    let mut common_prefixes = Vec::new();
    pos = 0;
    while let Some(start) = xml[pos..].find("<CommonPrefixes>") {
        let start = pos + start;
        if let Some(end) = xml[start..].find("</CommonPrefixes>") {
            let prefix_xml = &xml[start..start + end + 17];
            if let Some(p) = extract_xml_value(prefix_xml, "Prefix") {
                common_prefixes.push(p);
            }
            pos = start + end + 17;
        } else {
            break;
        }
    }

    Ok(ListObjectsResult {
        name: bucket.to_string(),
        prefix,
        objects,
        common_prefixes,
        is_truncated,
        next_continuation_token: next_token,
    })
}

fn parse_copy_object_response(xml: &str) -> Result<CopyObjectResult> {
    let etag = extract_xml_value(xml, "ETag")
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default();
    
    let last_modified = extract_xml_value(xml, "LastModified")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);

    Ok(CopyObjectResult { etag, last_modified })
}

fn extract_xml_value(xml: &str, element: &str) -> Option<String> {
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
    fn test_parse_list_buckets() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>user123</ID>
        <DisplayName>Test User</DisplayName>
    </Owner>
    <Buckets>
        <Bucket>
            <Name>bucket1</Name>
            <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
        </Bucket>
    </Buckets>
</ListAllMyBucketsResult>"#;

        let result = parse_list_buckets_response(xml).unwrap();
        assert_eq!(result.owner_id, "user123");
        assert_eq!(result.buckets.len(), 1);
        assert_eq!(result.buckets[0].name, "bucket1");
    }
}
