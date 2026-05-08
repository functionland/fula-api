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
PER_BUCKET=0
PER_BUCKET_TIMEOUT="${PER_BUCKET_TIMEOUT:-120}"
for arg in "$@"; do
    case "$arg" in
        --dry-run-only)    DRY_RUN_ONLY=1 ;;
        --yes|-y)          ASSUME_YES=1 ;;
        --cleanup-cluster) CLEANUP_CLUSTER=1 ;;
        --per-bucket)
            # Iterate the dry-run's affected buckets one at a time,
            # using the handler's bucket_internal_key query parameter.
            # Each bucket is its own request → if one hangs, the rest
            # still get processed. Set PER_BUCKET_TIMEOUT (default 120s)
            # to bound how long any single bucket can wedge the script.
            PER_BUCKET=1
            ;;
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
if [[ "$PER_BUCKET" == "1" ]]; then
    # Per-bucket mode: enumerate the dry-run's affected buckets and
    # call the handler once per bucket via ?bucket_internal_key=. Each
    # bucket gets its own bounded request so a single wedged bucket
    # doesn't tie up the rest of the sweep. Aggregate results into a
    # single response shape so downstream code (old_root_cids capture +
    # error reporting) keeps working unchanged.
    BUCKETS_TO_PROCESS=$(echo "$DRY_RESP" | jq -r '(.details // []) | .[] | .bucket_internal_key')
    BUCKETS_COUNT=$(echo "$BUCKETS_TO_PROCESS" | grep -c . || true)
    echo "Per-bucket mode: ${BUCKETS_COUNT} bucket(s), ${PER_BUCKET_TIMEOUT}s timeout each" >&2
    LIVE_RESP='{"details":[]}'
    DONE=0
    while IFS= read -r bk; do
        [[ -z "$bk" ]] && continue
        DONE=$((DONE + 1))
        # urlencode the colon and any @ in the bucket key
        BK_ENC=$(printf '%s' "$bk" | sed 's/:/%3A/g; s/@/%40/g')
        echo "  [${DONE}/${BUCKETS_COUNT}] $bk" >&2
        JWT=$(mint_jwt)
        ONE_RESP=$(curl -sS -X POST \
            --max-time "$PER_BUCKET_TIMEOUT" \
            -H "Authorization: Bearer $JWT" \
            "$BASE/admin/pii-sweep?dry_run=false&bucket_internal_key=$BK_ENC" \
            2>/dev/null || true)
        if [[ -z "$ONE_RESP" ]] || ! echo "$ONE_RESP" | jq -e '.details' >/dev/null 2>&1; then
            # Timeout, network error, or non-JSON response — fabricate
            # a synthetic detail entry so the operator sees the bucket
            # in the WARNING list at the end and can investigate it.
            echo "    TIMEOUT or ERROR — bucket marked as needs-investigation" >&2
            ONE_RESP=$(jq -nc --arg k "$bk" \
                '{details:[{bucket_internal_key:$k,bucket_owner_id:"",bucket_name:"",objects_total:0,objects_with_leak:0,rewritten:0,old_root_cid:"",new_root_cid:null,errors:["per-bucket request timed out or failed; check master logs"]}]}')
        fi
        # Merge ONE_RESP.details into LIVE_RESP.details
        LIVE_RESP=$(jq -nc --argjson a "$LIVE_RESP" --argjson b "$ONE_RESP" \
            '{details: (($a.details // []) + ($b.details // []))}')
    done <<< "$BUCKETS_TO_PROCESS"
    echo "" >&2
    echo "Per-bucket sweep complete; aggregated response below:" >&2
else
    JWT=$(mint_jwt)
    LIVE_RESP=$(curl -fsS -X POST --max-time "$TIMEOUT" \
        -H "Authorization: Bearer $JWT" \
        "$BASE/admin/pii-sweep?dry_run=false")
fi

echo "$LIVE_RESP" | jq .

# Capture old_root_cids for cluster cleanup, but ONLY for buckets that
# successfully migrated (new_root_cid is non-null AND errors is empty).
# A bucket whose live migration errored is still pointing at its
# old_root_cid; unpinning that from cluster would orphan its metadata.
# The filter `.errors == [] and .new_root_cid != null` is the precise
# signal that the bucket fully transitioned and the old root is safe to
# unpin. Errored buckets are reported separately so the operator can
# inspect them.
SAFE_OLDS_JSON=$(echo "$LIVE_RESP" \
    | jq '[(.details // [])[]
           | select((.errors == null or .errors == [])
                    and (.new_root_cid != null and .new_root_cid != ""))
           | .old_root_cid]
          | unique')
echo "$SAFE_OLDS_JSON" | jq -r '.[]' > "$OLD_ROOTS_FILE"
OLD_COUNT=$(wc -l < "$OLD_ROOTS_FILE" | tr -d ' ')

# Surface errored buckets so the operator knows to investigate before
# any manual cleanup.
ERR_BUCKETS=$(echo "$LIVE_RESP" \
    | jq -r '[(.details // [])[]
              | select((.errors // []) | length > 0)
              | "\(.bucket_internal_key) — \(.errors | join("; "))"]
             | .[]')

echo "" >&2
echo "Wrote ${OLD_COUNT} unique old_root_cid(s) to $OLD_ROOTS_FILE" >&2
echo "  (only buckets where migration fully succeeded — old root is safe to unpin)" >&2
if [[ -n "$ERR_BUCKETS" ]]; then
    echo "" >&2
    echo "WARNING: the following buckets had errors and were NOT included in $OLD_ROOTS_FILE:" >&2
    echo "$ERR_BUCKETS" | sed 's/^/  - /' >&2
    echo "Their old_root_cid is still authoritative — DO NOT unpin manually." >&2
    echo "Investigate, fix, and re-run the live sweep; idempotency makes this safe." >&2
fi

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
