# Reproduce the 412 PreconditionFailed on a Windows host using the user's
# actual encryption key, against their existing bucket. No Android device,
# no FxFiles rebuild.
#
# Runs `repro_412_existing_bucket_e2e`, which:
#   1. Loads the user's existing forest for $env:FULA_BUCKET.
#   2. Performs $env:FULA_REPRO_WRITES (default 5) sequential small writes.
#   3. Each write trips the conditional-PUT path (Phase 1.5 page,
#      Phase 1.6 dir-index, Phase 2 root) — same paths FxFiles hits.
#
# Outcomes:
# - All writes PASS: the 412 is FxFiles-state-dependent (WAL on disk,
#   long-running in-memory page_index). Not reproducible from fresh state.
# - One or more 412: local reproducer. The new diag headers in
#   crates/fula-client/src/encryption.rs (now on every conditional-PUT
#   site, not just Phase 2 root) will let master's `412 diag` log line
#   show the SDK's actual prior_etag and body_cid for the failing PUT,
#   instead of `<no-sdk-rebuild>`.
#
# Setup (PowerShell, from repo root):
#   $env:FULA_JWT          = "eyJhbGciOiJI..."          # user's Fula JWT
#   $env:FULA_TEST_SECRET  = "<base64 of FxFiles Settings > Security >
#                              Encryption Key — NOT the JWT>"
#   $env:FULA_S3           = "https://s3.cloud.fx.land" # default; override only
#                                                       # if pointing at staging
#   $env:FULA_BUCKET       = "face-metadata"            # default; the bucket
#                                                       # currently hitting 412
#                                                       # for ehsan6sha
#   .\scripts\probe-412-with-key.ps1
#
# How to extract the encryption key from FxFiles:
#   1. FxFiles → Settings → Security → Encryption Key.
#   2. Long-press / Copy. The value is base64. Paste straight into
#      $env:FULA_TEST_SECRET (no decoding needed — the test base64-decodes).
#
# Output:
#   The script forwards the test's stderr verbatim. Look for:
#     - "[offline_e2e:single-object] phase 1a: UPLOAD"  — initial PUT
#     - "412 diag: if_match vs current vs body_cid"     — bug reproduced
#     - "match_if_match diag ... result=true"           — clean round-trip
#     - "PASS" with a list of files                     — bug NOT reproduced
#
# Hard-fails (the test panics with a clear diagnostic) when:
#   - FULA_TEST_SECRET is wrong → BucketNotFound (lookup_h mismatch)
#   - JWT expired or wrong user → 401 / 403
#   - Master unreachable → connect error

$ErrorActionPreference = 'Stop'

if (-not $env:FULA_JWT) {
    Write-Error "FULA_JWT env var is required (the user's Fula JWT)."
    exit 1
}
if (-not $env:FULA_TEST_SECRET) {
    Write-Error @"
FULA_TEST_SECRET env var is required.

It must be the base64-encoded 32-byte encryption key from FxFiles
Settings > Security > Encryption Key. NOT the JWT, NOT a password.

Without the right key the test will fail at BucketNotFound because the
bucket_lookup_h on master is bound to whatever key FxFiles used at upload.
"@
    exit 1
}

if (-not $env:FULA_S3)            { $env:FULA_S3 = "https://s3.cloud.fx.land" }
if (-not $env:FULA_BUCKET)        { $env:FULA_BUCKET = "images" }
if (-not $env:FULA_REPRO_WRITES)  { $env:FULA_REPRO_WRITES = "5" }

Write-Host "===== probe-412-with-key ====="
Write-Host "FULA_S3            = $env:FULA_S3"
Write-Host "FULA_BUCKET        = $env:FULA_BUCKET"
Write-Host "FULA_REPRO_WRITES  = $env:FULA_REPRO_WRITES"
Write-Host "FULA_JWT           = (set, $($env:FULA_JWT.Length) chars)"
Write-Host "FULA_TEST_SECRET   = (set, $($env:FULA_TEST_SECRET.Length) chars base64)"
Write-Host "==============================="
Write-Host ""

$crateDir = Join-Path $PSScriptRoot ".." | Resolve-Path
Push-Location $crateDir
try {
    # `--nocapture` surfaces the SDK's tracing output verbatim, including
    # the new `phase1.5 page conditional PUT diag` / `phase1.6 dir-index
    # conditional PUT diag` / `phase2 conditional PUT diag` lines — those
    # carry the SDK's prior_etag for the same PUT master will log on 412.
    cargo test -p fula-client --test offline_e2e --release `
        repro_412_existing_bucket_e2e `
        -- --ignored --nocapture
}
finally {
    Pop-Location
}
