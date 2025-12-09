//! S3 SDK Integration Example
//!
//! This example demonstrates how to use standard S3 clients with Fula gateway
//! by wrapping JWT tokens in AWS Signature V4 format.
//!
//! Fula supports two authentication methods:
//! 1. Bearer token: `Authorization: Bearer <jwt>` (simple, for HTTP clients)
//! 2. AWS Signature V4: `Authorization: AWS4-HMAC-SHA256 Credential=JWT:<jwt>/...`
//!    (for standard S3 clients like boto3, AWS CLI, aws-sdk-js)
//!
//! For AWS Sig V4, embed your JWT in the access key with a `JWT:` prefix.
//! The secret access key can be any non-empty value (it's not validated).
//!
//! Run with: cargo run --example s3_sdk_integration
//!
//! Prerequisites:
//! 1. Gateway running: cargo run -p fula-cli -- --no-auth
//!    (or with auth: cargo run -p fula-cli -- --jwt-secret your-secret)
//! 2. IPFS daemon running: ipfs daemon

use std::env;

fn main() {
    println!("{}", "═".repeat(80));
    println!("           S3 SDK INTEGRATION EXAMPLES FOR FULA GATEWAY");
    println!("{}", "═".repeat(80));
    println!();

    // Example JWT token (in production, get this from your auth provider)
    let jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzM1NjAwMDAwLCJzY29wZSI6InN0b3JhZ2U6cmVhZCBzdG9yYWdlOndyaXRlIn0.signature";
    
    let gateway_url = env::var("FULA_GATEWAY_URL")
        .unwrap_or_else(|_| "http://localhost:9000".to_string());

    println!("Gateway URL: {}", gateway_url);
    println!();

    print_python_boto3_example(&gateway_url, jwt_token);
    print_javascript_sdk_example(&gateway_url, jwt_token);
    print_aws_cli_example(&gateway_url, jwt_token);
    print_curl_example(&gateway_url, jwt_token);
    print_rust_client_example(&gateway_url, jwt_token);

    println!("{}", "═".repeat(80));
    println!("                          KEY POINTS");
    println!("{}", "═".repeat(80));
    println!();
    println!("1. Access Key ID format: JWT:<your-jwt-token>");
    println!("2. Secret Access Key: any non-empty value (e.g., 'not-used')");
    println!("3. Region: any valid region (e.g., 'us-east-1')");
    println!("4. The gateway extracts and validates the JWT from the access key");
    println!("5. Timestamp validation (x-amz-date) prevents replay attacks");
    println!();
}

fn print_python_boto3_example(gateway_url: &str, _jwt: &str) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ PYTHON (boto3)                                                              │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!(r#"
import boto3
import requests

# 1. Get JWT from your auth provider (Auth0, Keycloak, custom, etc.)
auth_response = requests.post('https://auth.example.com/oauth/token', data={{
    'grant_type': 'client_credentials',
    'client_id': 'your-client-id',
    'client_secret': 'your-client-secret',
    'audience': 'storage-api'
}})
jwt_token = auth_response.json()['access_token']

# 2. Configure boto3 with JWT embedded in access key
s3 = boto3.client('s3',
    endpoint_url='{gateway_url}',
    aws_access_key_id=f'JWT:{{jwt_token}}',
    aws_secret_access_key='not-used',  # Not validated when using JWT
    region_name='us-east-1'
)

# 3. Use S3 API normally!
s3.create_bucket(Bucket='my-bucket')
s3.put_object(Bucket='my-bucket', Key='hello.txt', Body=b'Hello from boto3!')
obj = s3.get_object(Bucket='my-bucket', Key='hello.txt')
print(obj['Body'].read())

# For encrypted uploads, use Fula's client-side encryption:
# pip install fula-client
from fula import EncryptedS3Client
encrypted = EncryptedS3Client(endpoint='{gateway_url}', jwt=jwt_token)
encrypted.put_encrypted('my-bucket', 'secret.txt', b'Encrypted data!')
"#, gateway_url = gateway_url);
    println!();
}

fn print_javascript_sdk_example(gateway_url: &str, _jwt: &str) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ JAVASCRIPT (AWS SDK v3)                                                     │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!(r#"
import {{ S3Client, PutObjectCommand, GetObjectCommand }} from "@aws-sdk/client-s3";

// 1. Get JWT from your auth provider
const authResponse = await fetch('https://auth.example.com/oauth/token', {{
  method: 'POST',
  headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
  body: new URLSearchParams({{
    grant_type: 'client_credentials',
    client_id: 'your-client-id',
    client_secret: 'your-client-secret',
    audience: 'storage-api'
  }})
}});
const {{ access_token }} = await authResponse.json();

// 2. Configure S3 client with JWT in access key
const s3 = new S3Client({{
  endpoint: "{gateway_url}",
  region: "us-east-1",
  forcePathStyle: true,  // Required for custom endpoints
  credentials: {{
    accessKeyId: `JWT:${{access_token}}`,
    secretAccessKey: "not-used"
  }}
}});

// 3. Use S3 API normally!
await s3.send(new PutObjectCommand({{
  Bucket: "my-bucket",
  Key: "hello.txt",
  Body: "Hello from JavaScript!"
}}));

const response = await s3.send(new GetObjectCommand({{
  Bucket: "my-bucket",
  Key: "hello.txt"
}}));
console.log(await response.Body.transformToString());
"#, gateway_url = gateway_url);
    println!();
}

fn print_aws_cli_example(gateway_url: &str, _jwt: &str) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ AWS CLI                                                                     │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!(r#"
# 1. Configure a profile with JWT in ~/.aws/credentials
cat >> ~/.aws/credentials << EOF
[fula]
aws_access_key_id = JWT:your-jwt-token-here
aws_secret_access_key = not-used
EOF

# 2. Use AWS CLI with the profile
aws s3 ls --endpoint-url {gateway_url} --profile fula

aws s3 cp hello.txt s3://my-bucket/hello.txt \
  --endpoint-url {gateway_url} \
  --profile fula

aws s3 cp s3://my-bucket/hello.txt downloaded.txt \
  --endpoint-url {gateway_url} \
  --profile fula

# Or use environment variables:
export AWS_ACCESS_KEY_ID="JWT:your-jwt-token"
export AWS_SECRET_ACCESS_KEY="not-used"
aws s3 ls --endpoint-url {gateway_url}
"#, gateway_url = gateway_url);
    println!();
}

fn print_curl_example(gateway_url: &str, _jwt: &str) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ CURL (Simple Bearer Token)                                                  │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!(r#"
# For simple HTTP clients, use Bearer token directly:

# List buckets
curl -H "Authorization: Bearer $JWT" {gateway_url}/

# Create bucket
curl -X PUT -H "Authorization: Bearer $JWT" {gateway_url}/my-bucket

# Upload file
curl -X PUT -H "Authorization: Bearer $JWT" \
  -d "Hello World" \
  {gateway_url}/my-bucket/hello.txt

# Download file
curl -H "Authorization: Bearer $JWT" {gateway_url}/my-bucket/hello.txt
"#, gateway_url = gateway_url);
    println!();
}

fn print_rust_client_example(gateway_url: &str, _jwt: &str) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ RUST (fula-client with encryption)                                          │");
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!(r#"
use fula_client::{{Config, FulaClient, EncryptedClient, EncryptionConfig}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {{
    // Simple client (Bearer token)
    let client = FulaClient::new(
        Config::new("{gateway_url}")
            .with_token("your-jwt-token")
    )?;
    
    client.create_bucket("my-bucket").await?;
    client.put_object("my-bucket", "hello.txt", b"Hello!".to_vec()).await?;
    
    // Encrypted client (client-side encryption + Bearer token)
    let encrypted = EncryptedClient::new(
        Config::new("{gateway_url}").with_token("your-jwt-token"),
        EncryptionConfig::new(),
    )?;
    
    encrypted.put_object_encrypted("my-bucket", "secret.txt", b"Encrypted!".to_vec()).await?;
    let data = encrypted.get_object_decrypted("my-bucket", "secret.txt").await?;
    
    Ok(())
}}
"#, gateway_url = gateway_url);
    println!();
}
