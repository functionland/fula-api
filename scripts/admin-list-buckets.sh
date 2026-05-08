#!/usr/bin/env bash
# Mint a short-lived admin JWT signed with ADMIN_JWT_SECRET and call
# /admin/users/{user_id}/buckets to dump every BucketMetadata for the user.
#
# Usage:
#   export ADMIN_JWT_SECRET="<the secret from /etc/fula/.env>"
#   export FULA_S3="https://s3.cloud.fx.land"   # optional default
#   export TARGET_USER="ehsan@fx.land"          # optional default
#   ./scripts/admin-list-buckets.sh
#
# Requires: openssl, jq (for pretty output; optional)

set -euo pipefail

if [[ -z "${ADMIN_JWT_SECRET:-}" ]]; then
    echo "ERROR: ADMIN_JWT_SECRET env var is required (source /etc/fula/.env)" >&2
    exit 1
fi

BASE="${FULA_S3:-https://s3.cloud.fx.land}"
TARGET="${TARGET_USER:-ehsan@fx.land}"

b64url() {
    # base64 → URL-safe (no padding, +→-, /→_)
    openssl base64 -A | tr -d '=' | tr '+/' '-_'
}

NOW=$(date +%s)
EXP=$((NOW + 300))
HEADER='{"alg":"HS256","typ":"JWT"}'
PAYLOAD='{"sub":"admin","scope":"admin","iat":'$NOW',"exp":'$EXP'}'

H=$(printf '%s' "$HEADER"  | b64url)
P=$(printf '%s' "$PAYLOAD" | b64url)
SIGNING_INPUT="$H.$P"

SIG=$(printf '%s' "$SIGNING_INPUT" \
    | openssl dgst -sha256 -mac HMAC -macopt "key:$ADMIN_JWT_SECRET" -binary \
    | b64url)

JWT="$SIGNING_INPUT.$SIG"

# urlencode the @ in the email — bash printf %% trick
ENCODED=$(printf '%s' "$TARGET" | sed 's/@/%40/g')

echo "Calling $BASE/admin/users/$TARGET/buckets" >&2
RESP=$(curl -fsS -H "Authorization: Bearer $JWT" "$BASE/admin/users/$ENCODED/buckets")

if command -v jq >/dev/null 2>&1; then
    echo "$RESP" | jq .
else
    echo "$RESP"
fi
