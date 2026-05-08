# Mint a short-lived admin JWT signed with ADMIN_JWT_SECRET and call
# /admin/users/{user_id}/buckets to dump every BucketMetadata for the user.
#
# Usage (PowerShell):
#   $env:ADMIN_JWT_SECRET = "<the secret from /etc/fula/.env>"
#   $env:FULA_S3 = "https://s3.cloud.fx.land"   # optional; this is the default
#   $env:TARGET_USER = "ehsan@fx.land"           # optional; this is the default
#   .\scripts\admin-list-buckets.ps1
#
# What it does:
#   1. Builds HS256 header + payload (sub=admin, scope=admin, exp=now+5min)
#   2. Signs with $env:ADMIN_JWT_SECRET via HMAC-SHA256
#   3. Calls GET /admin/users/<TARGET_USER>/buckets with the token
#   4. Prints the JSON response

$ErrorActionPreference = 'Stop'

if (-not $env:ADMIN_JWT_SECRET) {
    Write-Error "ADMIN_JWT_SECRET env var is required (export from /etc/fula/.env)"
    exit 1
}

$base = if ($env:FULA_S3) { $env:FULA_S3 } else { "https://s3.cloud.fx.land" }
$target = if ($env:TARGET_USER) { $env:TARGET_USER } else { "ehsan@fx.land" }

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$now = [int][double]::Parse((Get-Date -UFormat %s))
$exp = $now + 300  # 5 minutes
$headerJson  = '{"alg":"HS256","typ":"JWT"}'
$payloadJson = "{`"sub`":`"admin`",`"scope`":`"admin`",`"iat`":$now,`"exp`":$exp}"

$h = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($headerJson))
$p = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
$signingInput = "$h.$p"

$hmac = [System.Security.Cryptography.HMACSHA256]::new(
    [System.Text.Encoding]::UTF8.GetBytes($env:ADMIN_JWT_SECRET))
$sig = ConvertTo-Base64Url ($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signingInput)))

$jwt = "$signingInput.$sig"

Write-Host "Calling $base/admin/users/$target/buckets" -ForegroundColor Cyan
$encoded = [System.Uri]::EscapeDataString($target)
$resp = Invoke-RestMethod `
    -Method GET `
    -Uri "$base/admin/users/$encoded/buckets" `
    -Headers @{ Authorization = "Bearer $jwt" }

$resp | ConvertTo-Json -Depth 10
