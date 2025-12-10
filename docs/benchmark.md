E:\GitHub\fula-api>cargo run --example benchmark --release
   Compiling fula-client v0.1.0 (E:\GitHub\fula-api\crates\fula-client)
   Compiling fula-api v0.1.0 (E:\GitHub\fula-api)
    Finished `release` profile [optimized] target(s) in 1m 05s
     Running `target\release\examples\benchmark.exe`
════════════════════════════════════════════════════════════════════════════════
              FULA ENCRYPTED STORAGE BENCHMARK
════════════════════════════════════════════════════════════════════════════════

Configuration:
  ├─ Gateway: http://localhost:9000
  ├─ Small folders: 20 × 100 files
  ├─ Large file: 100 MB
  ├─ Deep structure: 10 levels × 10 files
  └─ Remote pinning: enabled

To customize, set environment variables:
  BENCHMARK_SMALL_FOLDERS, BENCHMARK_FILES_PER_FOLDER,
  BENCHMARK_LARGE_FILE_MB, BENCHMARK_DEEP_LEVELS


🔧 SETUP: Creating User A's encrypted client...
   ├─ Remote pinning enabled: https://api.cloud.fx.land
   └─ Bucket created: benchmark-user-a

📁 SCENARIO 1A: Uploading 20 folders × 100 files each...
   Folder 1/20: ✓ (100 files)
   Folder 2/20: ✓ (100 files)
   Folder 3/20: ✓ (100 files)
   Folder 4/20: ✓ (100 files)
   Folder 5/20: ✓ (100 files)
   Folder 6/20: ✓ (100 files)
   Folder 7/20: ✓ (100 files)
   Folder 8/20: ✓ (100 files)
   Folder 9/20: ✓ (100 files)
   Folder 10/20: ✓ (100 files)
   Folder 11/20: ✓ (100 files)
   Folder 12/20: ✓ (100 files)
   Folder 13/20: ✓ (100 files)
   Folder 14/20: ✓ (100 files)
   Folder 15/20: ✓ (100 files)
   Folder 16/20: ✓ (100 files)
   Folder 17/20: ✓ (100 files)
   Folder 18/20: ✓ (100 files)
   Folder 19/20: ✓ (100 files)
   Folder 20/20: ✓ (100 files)
   └─ Upload complete: 2000 files, 53.50 MB in 744.1056406s

   📋 Listing all directories...
   └─ Listed 20 directories in 1.9586ms

   📥 Downloading & decrypting sample files...
....................
   └─ Downloaded 200 files in 14.8787811s

📦 SCENARIO 1B: Uploading large file (100 MB)...
   ├─ Upload: 296.3246268s
   └─ Downloading & decrypting...
      └─ Download: 97.4642419s (100.00 MB verified)

🌲 SCENARIO 1C: Creating 10-level deep folder structure...
   ├─ Created 10 files at depth 10 in 10.5218297s
   └─ Listed deep directory in 1.4459ms (10 entries)

🔗 SCENARIO 2: Sharing Benchmark
   User A shares the deep folder with User B...

   👤 User B created (public key: Fv6Zp8DlLdTWJgb6BaBn...)

   📝 Method 1: Direct ShareToken Creation
      ├─ Token created: 183.4µs
      ├─ Share ID: 151e55db392c7368d1123759cf0e122f
      └─ Path scope: /deep/level_0/level_1/level_2/level_3/level_4/level_5/level_6/level_7/level_8/level_9

   📬 Method 2: Async Inbox Sharing
      ├─ Envelope created: 378.4µs
      ├─ Entry ID: b9967390e8326c4a5a4725660e22f7b6
      └─ Inbox path: /.fula/inbox/0b987176e51cdb7abb46bd664456024b/b9967390e8326c4a5a4725660e22f7b6.share

   👤 User B accepts the share...
      ├─ Share accepted: 163.2µs
      ├─ Path scope: /deep/level_0/level_1/level_2/level_3/level_4/level_5/level_6/level_7/level_8/level_9
      └─ Can read: true, Can write: false

   📬 User B checks inbox...
      ├─ Pending shares: 1
      ├─ From: Some("User A")
      ├─ Label: Some("Deep Folder Share")
      └─ Message: Some("Here's access to my deep nested folder!")

   📥 User B fetches shared folder content...
      ├─ Fetch time: 1.3388ms
      └─ Files accessible: 10

════════════════════════════════════════════════════════════════════════════════
                         BENCHMARK RESULTS SUMMARY
════════════════════════════════════════════════════════════════════════════════

📁 SCENARIO 1A: Small Files (20 folders × 100 files each)
   ├─ Files: 2000
   ├─ Total Size: 53.50 MB
   ├─ Encrypt + Upload: 744.1056406s
   ├─ Download + Decrypt: 14.8787811s
   ├─ List Directory: 1.9586ms
   └─ Upload Throughput: 0.07 MB/s

📦 SCENARIO 1B: Large File
   ├─ Size: 100.00 MB
   ├─ Encrypt + Upload: 296.3246268s
   ├─ Download + Decrypt: 97.4642419s
   ├─ Upload Throughput: 0.34 MB/s
   └─ Download Throughput: 1.03 MB/s

🌲 SCENARIO 1C: Deep Nested Structure (10 levels)
   ├─ Files at Bottom: 10
   ├─ Upload Time: 10.5218297s
   └─ List Directory: 1.4459ms

🔗 SCENARIO 2: Sharing Benchmark
   ├─ Share Token Creation: 183.4µs
   ├─ Inbox Enqueue Time: 378.4µs
   ├─ Share Acceptance: 163.2µs
   ├─ Shared Folder Fetch: 1.3388ms
   └─ Files Decrypted by Recipient: 10

📊 OVERALL SUMMARY
   ├─ Total Files: 2011
   ├─ Total Data: 153.50 MB
   └─ Total Benchmark Time: 1163.7834586s

⚡ PERFORMANCE METRICS
   ├─ Files/second: 1.73
   └─ Throughput: 0.13 MB/s