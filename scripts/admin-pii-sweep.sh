#!/usr/bin/env bash
# Mint an admin JWT from $ADMIN_JWT_SECRET and run the PII-sweep that
# replaces plaintext-email `owner_id` rows in bucket-registry metadata
# with the canonical 16-byte BLAKE3 hashed form. Two-phase by default:
# dry-run first, then prompt before the live sweep. Writes the old root
# CIDs that get superseded to /tmp/old_root_cids.txt for optional cluster
# cleanup (pass --cleanup-cluster to do the cleanup automatically when
# run on the master host with `docker exec ipfs_cluster …` access).
#
# Background:
#   Pre-fix uploads recorded `owner_id = ehsan@fx.land` (plaintext email)
#   in BucketMetadata. The post-fix code records the hashed form
#   (e.g. `4da2c0616b1d39660f9f94e145fbce4f`). Until you run this sweep,
#   the old plaintext rows stay live in the bucket registry CBOR pinned
#   to IPFS — the new code can't see them as PII because reads pass
#   through unchanged. The sweep walks every bucket, rewrites the rows,
#   commits a new registry root, and reports the old roots so the
#   operator can unpin them from cluster.
#
# Required env:
#   ADMIN_JWT_SECRET    — the HS256 secret from /etc/fula/.env on master.
#                         Same secret used for /admin endpoints; keep secret.
#
# Optional env:
#   FULA_S3             — master endpoint. Default https://s3.cloud.fx.land.
#                         Use http://127.0.0.1:9000 when running on the master.
#   PII_SWEEP_TIMEOUT   — curl timeout in seconds. Default 600 (10 min;
#                         the live sweep can take a while on busy registries).
#
# Flags:
#   --dry-run-only      Skip the live sweep; just show the dry-run preview.
#   --yes               Skip the live-sweep confirmation prompt.
#   --cleanup-cluster   After the live sweep, run
#                         docker exec ipfs_cluster ipfs-cluster-ctl pin rm <cid>
#                       for every old_root_cid the sweep produced. Requires
#                       the script to run on the master host with docker
#                       access. The pinning-service/cluster GC eventually
#                       prunes orphan pins on its own; this just speeds it up.
#
# Usage (on master):
#   export ADMIN_JWT_SECRET="<from /etc/fula/.env>"
#   export FULA_S3="http://127.0.0.1:9000"
#   ./scripts/admin-pii-sweep.sh                    # dry-run + prompt + live
#   ./scripts/admin-pii-sweep.sh --yes              # dry-run + live (no prompt)
#   ./scripts/admin-pii-sweep.sh --dry-run-only     # show preview only
#   ./scripts/admin-pii-sweep.sh --yes --cleanup-cluster
#                                                   # full pipeline incl. unpin
#
# Requires: openssl, curl, jq.

set -euo pipefail

DRY_RUN_ONLY=0
ASSUME_YES=0
CLEANUP_CLUSTER=0
for arg in "$@"; do
    case "$arg" in
        --dry-run-only)    DRY_RUN_ONLY=1 ;;
        --yes|-y)          ASSUME_YES=1 ;;
        --cleanup-cluster) CLEANUP_CLUSTER=1 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | sed 's/^# \{0,1\}//;/^set -/d'
            exit 0
            ;;
        *)
            echo "ERROR: unknown flag '$arg'. Run with -h for help." >&2
            exit 2
            ;;
    esac
done

if [[ -z "${ADMIN_JWT_SECRET:-}" ]]; then
    echo "ERROR: ADMIN_JWT_SECRET env var is required (source /etc/fula/.env)" >&2
    exit 1
fi
for tool in openssl curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

BASE="${FULA_S3:-https://s3.cloud.fx.land}"
TIMEOUT="${PII_SWEEP_TIMEOUT:-600}"
OLD_ROOTS_FILE="/tmp/old_root_cids.txt"

b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }

mint_jwt() {
    local now exp header payload h p signing_input sig
    now=$(date +%s)
    exp=$((now + 300))
    header='{"alg":"HS256","typ":"JWT"}'
    payload='{"sub":"admin","scope":"admin","iat":'$now',"exp":'$exp'}'
    h=$(printf '%s' "$header"  | b64url)
    p=$(printf '%s' "$payload" | b64url)
    signing_input="$h.$p"
    sig=$(printf '%s' "$signing_input" \
        | openssl dgst -sha256 -mac HMAC -macopt "key:$ADMIN_JWT_SECRET" -binary \
        | b64url)
    printf '%s.%s' "$signing_input" "$sig"
}

# Phase 1 — dry-run preview.
echo "===== PII sweep: dry-run preview =====" >&2
echo "endpoint = $BASE" >&2
echo "" >&2
JWT=$(mint_jwt)
DRY_RESP=$(curl -fsS -X POST --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $JWT" \
    "$BASE/admin/pii-sweep?dry_run=true")

echo "$DRY_RESP" | jq .

# Pull a quick summary so the operator sees the magnitude before
# committing. `details` may be a large array on the live sweep; keep
# the printout terse here.
DRY_BUCKETS=$(echo "$DRY_RESP" | jq -r '.affected_bucket_count // (.details | length) // 0')
DRY_USERS=$(echo "$DRY_RESP"   | jq -r '.affected_user_count   // 0')
echo "" >&2
echo "Dry-run summary: ${DRY_BUCKETS} bucket(s) across ${DRY_USERS} user(s) need rewriting." >&2

if [[ "$DRY_BUCKETS" == "0" ]]; then
    echo "Nothing to do — no plaintext-email owner_ids found in the live registry." >&2
    exit 0
fi

if [[ "$DRY_RUN_ONLY" == "1" ]]; then
    echo "(--dry-run-only) Stopping here without applying changes." >&2
    exit 0
fi

# Phase 2 — confirmation gate.
if [[ "$ASSUME_YES" != "1" ]]; then
    echo "" >&2
    read -r -p "Proceed with the LIVE sweep (writes a new registry root)? [type 'yes' to continue] " ans
    if [[ "$ans" != "yes" ]]; then
        echo "Aborted by operator." >&2
        exit 1
    fi
fi

# Phase 3 — live sweep. Mint a fresh JWT (the dry-run one may be
# nearing its 5-minute expiry if the operator paused at the prompt).
echo "" >&2
echo "===== PII sweep: live =====" >&2
JWT=$(mint_jwt)
LIVE_RESP=$(curl -fsS -X POST --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $JWT" \
    "$BASE/admin/pii-sweep?dry_run=false")

echo "$LIVE_RESP" | jq .

# Capture old_root_cids for cluster cleanup. The endpoint emits one entry
# per affected bucket under `details[]` — the schema may be either
# `{ old_root_cid, new_root_cid, ... }` or a `{ before, after }` shape;
# tolerate both via jq's `// .alt`.
echo "$LIVE_RESP" \
    | jq -r '(.details // []) | .[] | (.old_root_cid // .before.root_cid // empty)' \
    | grep -v '^$' \
    | sort -u > "$OLD_ROOTS_FILE"

OLD_COUNT=$(wc -l < "$OLD_ROOTS_FILE" | tr -d ' ')
echo "" >&2
echo "Wrote ${OLD_COUNT} unique old_root_cid(s) to $OLD_ROOTS_FILE" >&2

if [[ "$OLD_COUNT" == "0" ]]; then
    echo "No old root CIDs to clean up. Done." >&2
    exit 0
fi

# Phase 4 — optional cluster cleanup.
if [[ "$CLEANUP_CLUSTER" == "1" ]]; then
    echo "" >&2
    echo "===== Cluster cleanup (--cleanup-cluster) =====" >&2
    if ! command -v docker >/dev/null 2>&1; then
        echo "WARN: docker not found; skipping cluster cleanup. Run manually:" >&2
        echo "  while read cid; do docker exec ipfs_cluster ipfs-cluster-ctl pin rm \"\$cid\"; done < $OLD_ROOTS_FILE" >&2
        exit 0
    fi
    while IFS= read -r cid; do
        echo "  unpinning $cid" >&2
        docker exec ipfs_cluster ipfs-cluster-ctl pin rm "$cid" || true
    done < "$OLD_ROOTS_FILE"
    echo "Cluster cleanup done." >&2
else
    echo "" >&2
    echo "To accelerate cluster cleanup of the old pinned roots, run:" >&2
    echo "  while read cid; do docker exec ipfs_cluster ipfs-cluster-ctl pin rm \"\$cid\"; done < $OLD_ROOTS_FILE" >&2
    echo "Or re-run this script with --cleanup-cluster on the master host." >&2
fi
