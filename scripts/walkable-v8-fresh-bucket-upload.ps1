# Walkable-v8 fresh-bucket UPLOAD test (#20 / #89 follow-up, part 1 of 2).
#
# Mirrors the FxFiles encrypted upload flow: same EncryptedClient
# construction, same put_object_flat call site for every file
# (auto-dispatches single-block vs chunked at 768 KiB), same
# list_files_from_forest reader.
#
# Two phases:
#   * Phase 0 (opt-in via FULA_VERIFY_IMAGES_BUCKET=1) — list the user's
#     existing `images` bucket and assert ≥1 file. Requires the real
#     user secret (derived from email/sub/provider) so the forest
#     actually decrypts to the user's data.
#   * Phase 1 (always) — fresh bucket + 5 deterministic test files
#     spanning the chunk threshold (3 text + 1 medium binary +
#     1 chunked >768 KiB).
#
# After this completes:
#   1. Copy the FULA_TEST_BUCKET / FULA_TEST_SECRET it prints into your
#      shell.
#   2. (For cold-walk only) wait 5+ minutes for the publisher tick.
#   3. Run scripts/walkable-v8-fresh-bucket-walk.ps1.
#
# Required env (set before running):
#   $env:FULA_JWT  = "<JWT>"
#   $env:FULA_S3   = "https://s3.cloud.fx.land"
#
# Secret-source (precedence high → low; pick ONE):
#   A. Email-derived (matches FxFiles auth_service.dart:535-541
#      Argon2id("fula-files-v1", "{provider}:{userId}:{email}")) —
#      REQUIRED for Phase 0:
#        $env:FULA_TEST_PROVIDER  = "google"          # or "apple"
#        $env:FULA_TEST_OAUTH_SUB = "<oauth sub>"     # the provider's user id
#        $env:FULA_TEST_EMAIL     = "user@example.com"
#   B. Pre-derived 32-byte secret as base64 (legacy override; CANNOT
#      run Phase 0 because we cannot reproduce the master-side key from
#      the secret alone):
#        $env:FULA_TEST_SECRET = "<base64>"
#   C. (none of the above) — random; Phase 0 must stay disabled.
#
# Optional:
#   $env:FULA_TIMEOUT_SECS         = "60"
#   $env:FULA_TEST_BUCKET          = "walkable-v8-test-..."   # override gen'd
#   $env:FULA_VERIFY_IMAGES_BUCKET = "1"                       # enable Phase 0
#   $env:FULA_IMAGES_BUCKET        = "images"                  # bucket to verify

$ErrorActionPreference = 'Stop'

$required = @('FULA_JWT', 'FULA_S3')
$missing = @()
foreach ($v in $required) {
    if (-not (Get-Item -Path "env:$v" -ErrorAction SilentlyContinue)) { $missing += $v }
}
if ($missing.Count -gt 0) {
    Write-Error "Missing required env vars: $($missing -join ', ')"
    exit 1
}

# If Phase 0 is requested, ONE of the user-supplied secret paths must
# be set: random secrets cannot decrypt the user's existing forest.
$verifyImages = $env:FULA_VERIFY_IMAGES_BUCKET
$verifyOn = $verifyImages -and ($verifyImages -ieq '1' -or $verifyImages -ieq 'true' -or $verifyImages -ieq 'yes' -or $verifyImages -ieq 'on')
if ($verifyOn) {
    $hasDerived = $env:FULA_TEST_PROVIDER -and $env:FULA_TEST_OAUTH_SUB -and $env:FULA_TEST_EMAIL
    $hasOverride = [bool]$env:FULA_TEST_SECRET
    if (-not ($hasDerived -or $hasOverride)) {
        Write-Error @'
FULA_VERIFY_IMAGES_BUCKET=1 requires a user-supplied secret. Set EITHER:
  A. FULA_TEST_PROVIDER + FULA_TEST_OAUTH_SUB + FULA_TEST_EMAIL
     (derives the same key FxFiles computes), OR
  B. FULA_TEST_SECRET = <base64 of your 32-byte encryption key>
     (copy it from FxFiles' SecureStorage `encryptionKey` entry —
     same bytes the app uses; bypasses needing the OAuth sub).
'@
        exit 1
    }
}

Write-Host "===== fxfiles_walkable_v8_fresh_bucket_upload ====="
Write-Host "FULA_S3                       = $env:FULA_S3"
Write-Host "FULA_JWT                      = (set, $($env:FULA_JWT.Length) chars)"
if ($env:FULA_TEST_PROVIDER) {
    Write-Host "FULA_TEST_PROVIDER            = $env:FULA_TEST_PROVIDER"
    Write-Host "FULA_TEST_OAUTH_SUB           = (set, $($env:FULA_TEST_OAUTH_SUB.Length) chars)"
    Write-Host "FULA_TEST_EMAIL               = $env:FULA_TEST_EMAIL"
    Write-Host "  (secret will be Argon2id-derived; matches FxFiles)"
} elseif ($env:FULA_TEST_SECRET) {
    Write-Host "FULA_TEST_SECRET (override)   = (set, $($env:FULA_TEST_SECRET.Length) chars, base64)"
} else {
    Write-Host "secret                        = (will be randomly generated)"
}
if ($env:FULA_TEST_BUCKET) {
    Write-Host "FULA_TEST_BUCKET (override)   = $env:FULA_TEST_BUCKET"
}
if ($verifyOn) {
    $imgBucket = if ($env:FULA_IMAGES_BUCKET) { $env:FULA_IMAGES_BUCKET } else { "images" }
    Write-Host "FULA_VERIFY_IMAGES_BUCKET     = on (will verify '$imgBucket' has files)"
}
Write-Host "===================================================="

$crateDir = Join-Path $PSScriptRoot ".." | Resolve-Path
Push-Location $crateDir
try {
    cargo test -p fula-client `
        --test offline_e2e --release `
        fxfiles_walkable_v8_fresh_bucket_upload `
        -- --ignored --nocapture
}
finally {
    Pop-Location
}
