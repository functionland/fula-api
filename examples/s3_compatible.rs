//! S3 SDK compatibility example
//!
//! This example shows that the Fula gateway is compatible with standard
//! S3 tools and SDKs. You can use:
//! - AWS CLI
//! - boto3 (Python)
//! - AWS SDK for JavaScript
//! - MinIO Client
//! - Any S3-compatible tool
//!
//! Run with: cargo run --example s3_compatible

fn main() {
    println!("🔌 Fula Storage - S3 Compatibility Guide\n");

    println!("The Fula gateway is fully S3-compatible. Here's how to use it with various tools:\n");

    // ==================== AWS CLI ====================
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("📌 AWS CLI");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("Configure AWS CLI to use Fula gateway:");
    println!("```bash");
    println!("# Set endpoint URL");
    println!("export AWS_ENDPOINT_URL=http://localhost:9000");
    println!("");
    println!("# Or use --endpoint-url flag");
    println!("aws --endpoint-url http://localhost:9000 s3 ls");
    println!("```\n");

    println!("Common operations:");
    println!("```bash");
    println!("# List buckets");
    println!("aws --endpoint-url http://localhost:9000 s3 ls");
    println!("");
    println!("# Create bucket");
    println!("aws --endpoint-url http://localhost:9000 s3 mb s3://my-bucket");
    println!("");
    println!("# Upload file");
    println!("aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://my-bucket/");
    println!("");
    println!("# Download file");
    println!("aws --endpoint-url http://localhost:9000 s3 cp s3://my-bucket/file.txt .");
    println!("");
    println!("# List objects");
    println!("aws --endpoint-url http://localhost:9000 s3 ls s3://my-bucket/");
    println!("");
    println!("# Sync directory");
    println!("aws --endpoint-url http://localhost:9000 s3 sync ./local-dir s3://my-bucket/backup/");
    println!("```\n");

    // ==================== Python boto3 ====================
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("🐍 Python (boto3)");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("```python");
    println!("import boto3");
    println!("from botocore.config import Config");
    println!("");
    println!("# Create S3 client pointing to Fula gateway");
    println!("s3 = boto3.client(");
    println!("    's3',");
    println!("    endpoint_url='http://localhost:9000',");
    println!("    aws_access_key_id='any',  # Not used, but required by boto3");
    println!("    aws_secret_access_key='any',");
    println!("    config=Config(signature_version='s3v4')");
    println!(")");
    println!("");
    println!("# Or with custom headers for JWT auth");
    println!("from botocore.handlers import set_auth_header");
    println!("");
    println!("def add_auth_header(request, **kwargs):");
    println!("    request.headers['Authorization'] = 'Bearer YOUR_JWT_TOKEN'");
    println!("");
    println!("s3.meta.events.register('before-sign.s3.*', add_auth_header)");
    println!("");
    println!("# List buckets");
    println!("response = s3.list_buckets()");
    println!("for bucket in response['Buckets']:");
    println!("    print(bucket['Name'])");
    println!("");
    println!("# Upload file");
    println!("s3.upload_file('local-file.txt', 'my-bucket', 'remote-file.txt')");
    println!("");
    println!("# Download file");
    println!("s3.download_file('my-bucket', 'remote-file.txt', 'downloaded.txt')");
    println!("```\n");

    // ==================== JavaScript ====================
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("📜 JavaScript (AWS SDK v3)");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("```javascript");
    println!("import {{ S3Client, ListBucketsCommand, PutObjectCommand }} from '@aws-sdk/client-s3';");
    println!("");
    println!("// Create client");
    println!("const client = new S3Client({{");
    println!("    endpoint: 'http://localhost:9000',");
    println!("    region: 'us-east-1',");
    println!("    credentials: {{");
    println!("        accessKeyId: 'any',");
    println!("        secretAccessKey: 'any',");
    println!("    }},");
    println!("    forcePathStyle: true,");
    println!("}});");
    println!("");
    println!("// Add JWT auth via middleware");
    println!("client.middlewareStack.add(");
    println!("    (next) => async (args) => {{");
    println!("        args.request.headers['Authorization'] = `Bearer ${{JWT_TOKEN}}`;");
    println!("        return next(args);");
    println!("    }},");
    println!("    {{ step: 'build', name: 'addAuthHeader' }}");
    println!(");");
    println!("");
    println!("// List buckets");
    println!("const buckets = await client.send(new ListBucketsCommand({{}}));");
    println!("console.log(buckets.Buckets);");
    println!("");
    println!("// Upload object");
    println!("await client.send(new PutObjectCommand({{");
    println!("    Bucket: 'my-bucket',");
    println!("    Key: 'hello.txt',");
    println!("    Body: 'Hello, World!',");
    println!("}}));");
    println!("```\n");

    // ==================== curl ====================
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("🌐 curl");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("```bash");
    println!("# List buckets");
    println!("curl -H \"Authorization: Bearer $TOKEN\" http://localhost:9000/");
    println!("");
    println!("# Create bucket");
    println!("curl -X PUT -H \"Authorization: Bearer $TOKEN\" http://localhost:9000/my-bucket");
    println!("");
    println!("# Upload object");
    println!("curl -X PUT -H \"Authorization: Bearer $TOKEN\" \\");
    println!("     -H \"Content-Type: text/plain\" \\");
    println!("     --data-binary @file.txt \\");
    println!("     http://localhost:9000/my-bucket/file.txt");
    println!("");
    println!("# Download object");
    println!("curl -H \"Authorization: Bearer $TOKEN\" \\");
    println!("     http://localhost:9000/my-bucket/file.txt -o downloaded.txt");
    println!("");
    println!("# List objects");
    println!("curl -H \"Authorization: Bearer $TOKEN\" \\");
    println!("     \"http://localhost:9000/my-bucket?list-type=2\"");
    println!("```\n");

    // ==================== MinIO Client ====================
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("🪣 MinIO Client (mc)");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("```bash");
    println!("# Configure alias");
    println!("mc alias set fula http://localhost:9000 any any");
    println!("");
    println!("# List buckets");
    println!("mc ls fula");
    println!("");
    println!("# Create bucket");
    println!("mc mb fula/my-bucket");
    println!("");
    println!("# Upload file");
    println!("mc cp file.txt fula/my-bucket/");
    println!("");
    println!("# Download file");
    println!("mc cp fula/my-bucket/file.txt .");
    println!("");
    println!("# Mirror directory");
    println!("mc mirror ./local-dir fula/my-bucket/backup/");
    println!("```\n");

    println!("═══════════════════════════════════════════════════════════════");
    println!("✨ The Fula gateway supports all standard S3 operations!");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    println!("Supported operations:");
    println!("  ✅ CreateBucket / DeleteBucket / HeadBucket / ListBuckets");
    println!("  ✅ PutObject / GetObject / DeleteObject / HeadObject / CopyObject");
    println!("  ✅ ListObjectsV2 with prefix, delimiter, and pagination");
    println!("  ✅ Multipart uploads (CreateMultipartUpload, UploadPart, CompleteMultipartUpload)");
    println!("  ✅ Object tagging and metadata");
    println!("");
    println!("Coming soon:");
    println!("  🔜 Presigned URLs");
    println!("  🔜 Bucket policies");
    println!("  🔜 Object versioning");
    println!("  🔜 Server-side encryption");
}
