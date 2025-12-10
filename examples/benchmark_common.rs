// Common utilities for benchmark examples
// This file is included via include!() in other benchmark files

use fula_client::{Config, EncryptedClient, EncryptionConfig, KeyObfuscation, PinningCredentials};

/// Benchmark configuration from environment variables
pub struct BenchmarkConfig {
    pub gateway_url: String,
    pub small_folders: usize,
    pub files_per_folder: usize,
    pub large_file_mb: usize,
    pub deep_levels: usize,
    pub files_at_bottom: usize,
    pub parallel_files: usize,
    pub parallel_concurrency: usize,
    pub pinning_endpoint: Option<String>,
    pub pinning_token: Option<String>,
}

impl BenchmarkConfig {
    pub fn from_env() -> Self {
        Self {
            gateway_url: env::var("BENCHMARK_GATEWAY_URL")
                .unwrap_or_else(|_| "http://localhost:9000".to_string()),
            small_folders: env::var("BENCHMARK_SMALL_FOLDERS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(20),
            files_per_folder: env::var("BENCHMARK_FILES_PER_FOLDER")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(100),
            large_file_mb: env::var("BENCHMARK_LARGE_FILE_MB")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(100),
            deep_levels: env::var("BENCHMARK_DEEP_LEVELS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(10),
            files_at_bottom: env::var("BENCHMARK_FILES_AT_BOTTOM")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(10),
            parallel_files: env::var("BENCHMARK_PARALLEL_FILES")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(100),
            parallel_concurrency: env::var("BENCHMARK_PARALLEL_CONCURRENCY")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(10),
            pinning_endpoint: env::var("PINNING_SERVICE_ENDPOINT").ok(),
            pinning_token: env::var("PINNING_SERVICE_TOKEN").ok(),
        }
    }

    pub fn has_pinning(&self) -> bool {
        self.pinning_endpoint.is_some() && self.pinning_token.is_some()
    }
}

/// Create an encrypted client with optional pinning
pub fn create_client(config: &BenchmarkConfig) -> anyhow::Result<EncryptedClient> {
    let encryption = EncryptionConfig::new()
        .with_obfuscation_mode(KeyObfuscation::FlatNamespace);
    
    let client_config = Config::new(&config.gateway_url);
    
    if config.has_pinning() {
        let pinning = PinningCredentials::new(
            config.pinning_endpoint.as_ref().unwrap(),
            config.pinning_token.as_ref().unwrap(),
        );
        Ok(EncryptedClient::new_with_pinning(client_config, encryption, pinning)?)
    } else {
        Ok(EncryptedClient::new(client_config, encryption)?)
    }
}

/// Generate deterministic random data
pub fn generate_random_data(size: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut data = vec![0u8; size];
    let mut hasher = DefaultHasher::new();
    
    for (i, chunk) in data.chunks_mut(8).enumerate() {
        i.hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte = hash[j % 8];
        }
    }
    data
}

/// Generate varying file sizes for small files
pub fn generate_small_file_size(index: usize) -> usize {
    let sizes = [1024, 2048, 4096, 8192, 16384, 32768, 65536, 102400];
    sizes[index % sizes.len()]
}

/// Format bytes for display
pub fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}
