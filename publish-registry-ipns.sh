#!/bin/bash
# Publishes the latest fula-gateway registry CID to IPNS every 10 minutes.
#
# One-time setup (run manually first):
#   docker exec ipfs_host ipfs key gen fula-registry
#
# Cron entry (every 10 min):
#   */10 * * * * /opt/fula-api/publish-registry-ipns.sh >> /var/log/fula-registry-ipns.log 2>&1

set -euo pipefail

CID_FILE="/var/lib/fula-gateway/registry.cid"
IPNS_KEY="fula-registry"
CONTAINER="ipfs_host"

# Read CID -- file is <100 bytes, single-syscall read, won't block concurrent writes
CID=$(cat "$CID_FILE" 2>/dev/null | tr -d '[:space:]') || true

if [[ -z "$CID" ]]; then
    echo "$(date -Iseconds) SKIP: empty or missing $CID_FILE"
    exit 0
fi

# Validate CID format (CIDv0 starts with Qm, CIDv1 starts with bafy/bafk/bagb etc.)
if [[ ! "$CID" =~ ^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$ ]]; then
    echo "$(date -Iseconds) SKIP: invalid CID format: $CID"
    exit 0
fi

# Publish to IPNS (--lifetime slightly over 10 min so records overlap)
OUTPUT=$(docker exec "$CONTAINER" ipfs name publish \
    --key="$IPNS_KEY" \
    --lifetime=20m \
    --quieter \
    "/ipfs/$CID" 2>&1) || {
    echo "$(date -Iseconds) ERROR: ipfs name publish failed: $OUTPUT"
    exit 1
}

echo "$(date -Iseconds) OK: published $CID -> /ipns/$OUTPUT"
