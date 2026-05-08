# Mirror FxFiles' "open a bucket in cloud-storage screen while offline" path.
# Calls EncryptedClient::load_forest + list_files_from_forest exactly the way
# fula_api_service.dart does on the device, against the LIVE published IPNS
# CBOR for ehsan@fx.land. No master, no warm cache — pure cold-start.
#
# Required env (set before running):
#   $env:FULA_TEST_SECRET                = "<base64 from FxFiles Settings>"
#   $env:FULA_JWT                        = "<ehsan@fx.land's JWT>"
#   $env:FULA_USERS_INDEX_USER_KEY       = "4da2c0616b1d39660f9f94e145fbce4f"
#   $env:FULA_USERS_INDEX_IPNS_NAME      = "k51qzi5uqu5dkkd6tv8slgoouzzs505qdcr4cb5egc9rlx7qwq0e794yxj9cg4"
#   $env:FULA_USERS_INDEX_CHAIN_RPC_URL  = "https://mainnet.base.org"
#   $env:FULA_USERS_INDEX_ANCHOR_ADDRESS = "0x..."
#
# Optional:
#   $env:FULA_BUCKET = "images"   # default; pick a bucket that has
#                                 # forest_manifest_cid populated (images,
#                                 # face-metadata, other in ehsan's index)
#
# Output: prints what each step (load_forest, list_files_from_forest)
# returned + the first 20 entries. Reports EMPTY-FOREST if 0 files surfaced
# despite the bucket being known to contain files.

$ErrorActionPreference = 'Stop'

$required = @(
    'FULA_TEST_SECRET',
    'FULA_JWT',
    'FULA_USERS_INDEX_USER_KEY',
    'FULA_USERS_INDEX_IPNS_NAME',
    'FULA_USERS_INDEX_CHAIN_RPC_URL',
    'FULA_USERS_INDEX_ANCHOR_ADDRESS'
)
$missing = @()
foreach ($v in $required) {
    if (-not (Get-Item -Path "env:$v" -ErrorAction SilentlyContinue)) { $missing += $v }
}
if ($missing.Count -gt 0) {
    Write-Error "Missing required env vars: $($missing -join ', ')"
    exit 1
}

if (-not $env:FULA_BUCKET) { $env:FULA_BUCKET = 'images' }

Write-Host "===== fxfiles_offline_open_bucket ====="
Write-Host "FULA_BUCKET                    = $env:FULA_BUCKET"
Write-Host "FULA_USERS_INDEX_USER_KEY      = $env:FULA_USERS_INDEX_USER_KEY"
Write-Host "FULA_USERS_INDEX_IPNS_NAME     = $env:FULA_USERS_INDEX_IPNS_NAME"
Write-Host "FULA_USERS_INDEX_CHAIN_RPC_URL = $env:FULA_USERS_INDEX_CHAIN_RPC_URL"
Write-Host "FULA_USERS_INDEX_ANCHOR_ADDRESS= $env:FULA_USERS_INDEX_ANCHOR_ADDRESS"
Write-Host "FULA_TEST_SECRET               = (set, $($env:FULA_TEST_SECRET.Length) chars)"
Write-Host "FULA_JWT                       = (set, $($env:FULA_JWT.Length) chars)"
Write-Host "========================================"

$crateDir = Join-Path $PSScriptRoot ".." | Resolve-Path
Push-Location $crateDir
try {
    # `--features test-fault-injection` enables the gated
    # `sharded_forest_diagnostic` accessor so step 1.5 prints the
    # total_shards / shards_with_root / sequence numbers that
    # distinguish "empty published manifest" from "walk silently
    # dropping entries".
    cargo test -p fula-client --features test-fault-injection `
        --test offline_e2e --release `
        fxfiles_offline_open_bucket `
        -- --ignored --nocapture
}
finally {
    Pop-Location
}
