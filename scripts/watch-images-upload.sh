#!/usr/bin/env bash
# Run on the master, then upload an image from FxFiles. This tails the
# gateway log filtered to lines that pinpoint where Phase 1.2 / v0.5.0
# migration is succeeding or failing for the user's `images` bucket:
#
#   * "Populated/updated bucket_lookup_h" — Phase 1.2 ran (good — appears on first-flush AND on key-rotation flushes)
#   * "Populated forest_manifest_cid" — v0.5.0 ran (good — should appear on every Phase 2 root commit)
#   * "populate_bucket_lookup_h failed"
#   * "populate_forest_manifest_cid failed"
#   * "Failed to flush bucket"
#   * "Failed to persist bucket registry"
#   * "concurrent modification" / "412"
#   * "ConcurrentModificationExhausted"
#   * any error/warning mentioning bucket=images
#
# Stops via Ctrl-C.

set -euo pipefail

CONTAINER="${CONTAINER:-fula-gateway-1}"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "ERROR: container $CONTAINER not running. Override with CONTAINER=<name>." >&2
    docker ps --format '{{.Names}}' >&2
    exit 1
fi

# Pre-flight: env flag check
echo "===== Env flag check (in-container) =====" >&2
docker exec "$CONTAINER" sh -c 'echo "FULA_BUCKET_LOOKUP_H_ENABLED=${FULA_BUCKET_LOOKUP_H_ENABLED:-<unset>}"; echo "FULA_FOREST_MANIFEST_CID_ENABLED=${FULA_FOREST_MANIFEST_CID_ENABLED:-<unset>}"; echo "FULA_USERS_INDEX_PUBLISHER_ENABLED=${FULA_USERS_INDEX_PUBLISHER_ENABLED:-<unset>}"' >&2 || true
echo "" >&2

echo "===== Tailing $CONTAINER (Ctrl-C to stop). Now upload an image from FxFiles. =====" >&2
echo "" >&2

docker logs --since 5s -f "$CONTAINER" 2>&1 | grep --line-buffered -iE \
    'images|bucket_lookup_h|forest_manifest_cid|flush.*bucket|persist.*registry|concurrent modification|412 Precondition|ConcurrentModificationExhausted|put_object_flat|Phase ?2|save_(sharded_hamt_)?forest|Populated|Restoring bucket|BucketAlreadyExists|match_if_match diag|conditional PUT diag|GET diag|PUT diag|412 diag|sdk_debug|fula-debug'
