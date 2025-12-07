//! Multipart upload support for large files

use crate::{ClientError, FulaClient, Result};
use bytes::Bytes;
use std::sync::Arc;

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(UploadProgress) + Send + Sync>;

/// Upload progress information
#[derive(Clone, Debug)]
pub struct UploadProgress {
    /// Bytes uploaded so far
    pub bytes_uploaded: u64,
    /// Total bytes to upload
    pub total_bytes: u64,
    /// Current part number
    pub current_part: u32,
    /// Total number of parts
    pub total_parts: u32,
}

impl UploadProgress {
    /// Get percentage complete
    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        (self.bytes_uploaded as f64 / self.total_bytes as f64) * 100.0
    }
}

/// Multipart upload handle
pub struct MultipartUpload {
    client: Arc<FulaClient>,
    bucket: String,
    key: String,
    upload_id: String,
    parts: Vec<CompletedPart>,
    #[allow(dead_code)]
    chunk_size: u64,
}

#[derive(Clone, Debug)]
struct CompletedPart {
    part_number: u32,
    etag: String,
}

impl MultipartUpload {
    /// Start a new multipart upload
    pub async fn start(
        client: Arc<FulaClient>,
        bucket: &str,
        key: &str,
    ) -> Result<Self> {
        // Initiate multipart upload
        let upload_id = initiate_upload(&client, bucket, key).await?;
        let chunk_size = client.config().multipart_chunk_size;

        Ok(Self {
            client,
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id,
            parts: Vec::new(),
            chunk_size,
        })
    }

    /// Upload a part
    pub async fn upload_part(&mut self, part_number: u32, data: Bytes) -> Result<()> {
        let etag = upload_part(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            part_number,
            data,
        ).await?;

        self.parts.push(CompletedPart { part_number, etag });
        Ok(())
    }

    /// Complete the upload
    pub async fn complete(self) -> Result<String> {
        complete_upload(
            &self.client,
            &self.bucket,
            &self.key,
            &self.upload_id,
            &self.parts,
        ).await
    }

    /// Abort the upload
    pub async fn abort(self) -> Result<()> {
        abort_upload(&self.client, &self.bucket, &self.key, &self.upload_id).await
    }

    /// Get the upload ID
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    /// Get the number of completed parts
    pub fn completed_parts(&self) -> usize {
        self.parts.len()
    }
}

/// Upload a large file using multipart upload
pub async fn upload_large_file(
    client: Arc<FulaClient>,
    bucket: &str,
    key: &str,
    data: Bytes,
    progress: Option<ProgressCallback>,
) -> Result<String> {
    let chunk_size = client.config().multipart_chunk_size as usize;
    let total_size = data.len() as u64;
    let total_parts = ((data.len() + chunk_size - 1) / chunk_size) as u32;

    let mut upload = MultipartUpload::start(Arc::clone(&client), bucket, key).await?;

    let mut bytes_uploaded = 0u64;
    let mut part_number = 1u32;

    for chunk in data.chunks(chunk_size) {
        let chunk_data = Bytes::copy_from_slice(chunk);
        upload.upload_part(part_number, chunk_data).await?;

        bytes_uploaded += chunk.len() as u64;

        if let Some(ref cb) = progress {
            cb(UploadProgress {
                bytes_uploaded,
                total_bytes: total_size,
                current_part: part_number,
                total_parts,
            });
        }

        part_number += 1;
    }

    upload.complete().await
}

// Helper functions for multipart operations

async fn initiate_upload(client: &FulaClient, bucket: &str, key: &str) -> Result<String> {
    let path = format!("/{}/{}?uploads", bucket, key);
    
    // Build request manually since we need POST with query param
    let url = format!("{}{}", client.config().endpoint, path);
    
    let mut req = reqwest::Client::new().post(&url);
    
    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;
    
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(ClientError::from_s3_xml(&text, 500));
    }

    let text = response.text().await?;
    
    // Parse upload ID from XML
    let upload_id = extract_xml_value(&text, "UploadId")
        .ok_or_else(|| ClientError::InvalidResponse("Missing UploadId".to_string()))?;

    Ok(upload_id)
}

async fn upload_part(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    data: Bytes,
) -> Result<String> {
    let path = format!(
        "/{}/{}?partNumber={}&uploadId={}",
        bucket, key, part_number, upload_id
    );
    
    let url = format!("{}{}", client.config().endpoint, path);
    
    let mut req = reqwest::Client::new()
        .put(&url)
        .body(data);
    
    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;
    
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(ClientError::from_s3_xml(&text, 500));
    }

    let etag = response
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| ClientError::InvalidResponse("Missing ETag".to_string()))?;

    Ok(etag)
}

async fn complete_upload(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[CompletedPart],
) -> Result<String> {
    let path = format!("/{}/{}?uploadId={}", bucket, key, upload_id);
    
    // Build completion XML
    let mut xml = String::from("<CompleteMultipartUpload>");
    for part in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>\"{}\"</ETag></Part>",
            part.part_number, part.etag
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");

    let url = format!("{}{}", client.config().endpoint, path);
    
    let mut req = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", "application/xml")
        .body(xml);
    
    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;
    
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(ClientError::from_s3_xml(&text, 500));
    }

    let text = response.text().await?;
    
    let etag = extract_xml_value(&text, "ETag")
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| ClientError::InvalidResponse("Missing ETag".to_string()))?;

    Ok(etag)
}

async fn abort_upload(
    client: &FulaClient,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<()> {
    let path = format!("/{}/{}?uploadId={}", bucket, key, upload_id);
    let url = format!("{}{}", client.config().endpoint, path);
    
    let mut req = reqwest::Client::new().delete(&url);
    
    if let Some(token) = &client.config().access_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(ClientError::Http)?;
    
    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(ClientError::from_s3_xml(&text, 500));
    }

    Ok(())
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
