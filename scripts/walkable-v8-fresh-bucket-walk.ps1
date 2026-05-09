# Walkable-v8 fresh-bucket WALK test (#20 / #89 follow-up, part 2 of 2).
# Reads the bucket + secret produced by the upload script, then runs:
#   * Phase B (online list + download — always)
#   * Phase C (warm-cache offline — if -Mode warm or both)
#   * Phase D (cold-cache offline — if -Mode cold or both, requires
#     publisher tick + cold-start env vars)
#
# Required env (set before running):
#   $env:FULA_JWT          = "<JWT>"
#   $env:FULA_S3           = "https://s3.cloud.fx.land"
#   $env:FULA_TEST_BUCKET  = "<bucket from upload script>"
#   $env:FULA_TEST_SECRET  = "<base64 secret from upload script>"
#
# Optional:
#   $env:FULA_TIMEOUT_SECS = "60"
#   $env:FULA_WALK_MODE    = "warm" | "cold" | "both"   # default warm
#
# For cold-walk (Phase D), additionally set ALL of:
#   $env:FULA_BLOCK_GATEWAY_URLS         = "https://ipfs.cloud.fx.land/gateway/{cid}"
#   $env:FULA_USERS_INDEX_CHAIN_RPC_URL  = "https://mainnet.base.org"
#   $env:FULA_USERS_INDEX_ANCHOR_ADDRESS = "0x..."
#   $env:FULA_USERS_INDEX_IPNS_NAME      = "k51qzi5..."
#   $env:FULA_USERS_INDEX_USER_KEY       = "<32 hex>"
# Optional:
#   $env:FULA_USERS_INDEX_IPNS_GATEWAY_URLS = "<comma-separated>"
#
# Convenience flag: pass -Mode {warm|cold|both} to override FULA_WALK_MODE.

param(
    [ValidateSet('warm','cold','both')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'

if ($Mode) { $env:FULA_WALK_MODE = $Mode }
if (-not $env:FULA_WALK_MODE) { $env:FULA_WALK_MODE = 'warm' }

$required = @('FULA_JWT', 'FULA_S3', 'FULA_TEST_BUCKET', 'FULA_TEST_SECRET')
$missing = @()
foreach ($v in $required) {
    if (-not (Get-Item -Path "env:$v" -ErrorAction SilentlyContinue)) { $missing += $v }
}
if ($missing.Count -gt 0) {
    Write-Error "Missing required env vars: $($missing -join ', '). Run walkable-v8-fresh-bucket-upload.ps1 first."
    exit 1
}

if ($env:FULA_WALK_MODE -eq 'cold' -or $env:FULA_WALK_MODE -eq 'both') {
    $coldRequired = @(
        'FULA_BLOCK_GATEWAY_URLS',
        'FULA_USERS_INDEX_CHAIN_RPC_URL',
        'FULA_USERS_INDEX_ANCHOR_ADDRESS',
        'FULA_USERS_INDEX_IPNS_NAME',
        'FULA_USERS_INDEX_USER_KEY'
    )
    $coldMissing = @()
    foreach ($v in $coldRequired) {
        if (-not (Get-Item -Path "env:$v" -ErrorAction SilentlyContinue)) { $coldMissing += $v }
    }
    if ($coldMissing.Count -gt 0) {
        Write-Error "FULA_WALK_MODE=$env:FULA_WALK_MODE requires cold-start env vars. Missing: $($coldMissing -join ', ')"
        exit 1
    }
}

Write-Host "===== fxfiles_walkable_v8_fresh_bucket_walk ====="
Write-Host "FULA_S3                = $env:FULA_S3"
Write-Host "FULA_TEST_BUCKET       = $env:FULA_TEST_BUCKET"
Write-Host "FULA_WALK_MODE         = $env:FULA_WALK_MODE"
Write-Host "FULA_TEST_SECRET       = (set, $($env:FULA_TEST_SECRET.Length) chars)"
Write-Host "FULA_JWT               = (set, $($env:FULA_JWT.Length) chars)"
if ($env:FULA_WALK_MODE -ne 'warm') {
    Write-Host "FULA_BLOCK_GATEWAY_URLS         = $env:FULA_BLOCK_GATEWAY_URLS"
    Write-Host "FULA_USERS_INDEX_USER_KEY       = $env:FULA_USERS_INDEX_USER_KEY"
    Write-Host "FULA_USERS_INDEX_IPNS_NAME      = $env:FULA_USERS_INDEX_IPNS_NAME"
    Write-Host "FULA_USERS_INDEX_CHAIN_RPC_URL  = $env:FULA_USERS_INDEX_CHAIN_RPC_URL"
    Write-Host "FULA_USERS_INDEX_ANCHOR_ADDRESS = $env:FULA_USERS_INDEX_ANCHOR_ADDRESS"
}
Write-Host "===================================================="

$crateDir = Join-Path $PSScriptRoot ".." | Resolve-Path
Push-Location $crateDir
try {
    cargo test -p fula-client `
        --test offline_e2e --release `
        fxfiles_walkable_v8_fresh_bucket_walk `
        -- --ignored --nocapture
}
finally {
    Pop-Location
}
