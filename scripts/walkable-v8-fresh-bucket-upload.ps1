# Walkable-v8 fresh-bucket UPLOAD test (#20 / #89 follow-up, part 1 of 2).
# Creates a fresh bucket, uploads the deterministic test file set, and
# prints copy-paste env vars for the matching walk script to consume.
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
# Optional:
#   $env:FULA_TIMEOUT_SECS = "60"
#   $env:FULA_TEST_BUCKET  = "walkable-v8-test-..."  # override generated name
#   $env:FULA_TEST_SECRET  = "<base64>"              # override generated random secret

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

Write-Host "===== fxfiles_walkable_v8_fresh_bucket_upload ====="
Write-Host "FULA_S3                = $env:FULA_S3"
Write-Host "FULA_JWT               = (set, $($env:FULA_JWT.Length) chars)"
if ($env:FULA_TEST_BUCKET) {
    Write-Host "FULA_TEST_BUCKET (override) = $env:FULA_TEST_BUCKET"
}
if ($env:FULA_TEST_SECRET) {
    Write-Host "FULA_TEST_SECRET (override) = (set, $($env:FULA_TEST_SECRET.Length) chars)"
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
