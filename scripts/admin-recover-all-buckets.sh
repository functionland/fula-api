#!/usr/bin/env bash
# admin-recover-all-buckets.sh — EMAIL-FREE fleet recovery of hard-loss bucket
# indexes for an S3-over-IPFS gateway.
#
# THE BRIDGE (why no email is needed) ─────────────────────────────────────────
#   A bucket's object index (a prolly tree) lost interior nodes to `ipfs repo
#   gc`, so S3 LIST returns 410. The objects still exist in the pinning Postgres
#   DB, but keyed by `pins.user_id = sha256(email)`, while the gateway keys the
#   bucket by `owner_id = hash_user_id(email)` (a DIFFERENT one-way hash). With
#   no plaintext email on the server, those two can't be connected directly.
#
#   BUT the bucket's `root_cid` and `forest_manifest_cid` are CONTENT CIDs that
#   appear on BOTH sides: the gateway registry knows them per bucket (owner_id
#   side), and the pinning DB pins them under `pins.user_id` (email side). So:
#       gateway  GET /admin/buckets   →  (owner_id, bucket, root_cid, manifest)
#       pin DB   cid ∈ {root, manifest} → pins.user_id        ← the bridge
#       pin DB   object:<bucket>/* under pins.user_id          → the entries
#       gateway  POST /admin/recover-bucket-index {owner_id, bucket, entries}
#   No email, no per-user identity guessing — works for the whole fleet.
#
#   The recovery endpoint is self-selecting + safe (force=false): it probes each
#   bucket and only rebuilds genuine hard-loss ones —
#       200 rebuilt | 412 skip-healthy | 404 owner/bucket-miss | 503 transient.
#   Re-running is safe (a rebuilt bucket probes healthy next time → 412).
#
# REQUIRED env ───────────────────────────────────────────────────────────────
#   ADMIN_JWT_SECRET   HS256 admin secret from /etc/fula/.env (gateway must have
#                      FULA_ADMIN_API=true). The script mints its own admin JWT.
#
# OPTIONAL env ───────────────────────────────────────────────────────────────
#   FULA_S3            Gateway base URL. Default http://127.0.0.1:9000 (master).
#   PG_CONTAINER       Pinning Postgres container. Default postgres-pinning.
#   PINNING_TOKEN      Pinning JWT for off-box replication of the rebuilt nodes.
#                      Optional — empty uses the no-token persist path (heals
#                      registry.cid + local-pins the index, gc-safe on master).
#   STATUS_EXCLUDE     Pin statuses excluded from the rebuilt index. Default
#                      'deleted','failed'.
#   ONLY_BUCKET        Restrict to this bucket name (across all owners).
#   ONLY_OWNER         Restrict to this owner_id (32-hex).
#   LOG                Per-bucket outcome log. Default /tmp/recover-all-<epoch>.log
#
# FLAGS ───────────────────────────────────────────────────────────────────────
#   --dry-run-only   List targets + bridge result + entry counts; POST nothing.
#   --yes | -y       Skip the pre-sweep confirmation prompt.
#   -h | --help      Show this header.
#
# USAGE (on master, as root over SSH — no sudo needed) ────────────────────────
#   export ADMIN_JWT_SECRET="$(grep -E '^[[:space:]]*ADMIN_JWT_SECRET=' /etc/fula/.env | head -1 | cut -d= -f2-)"
#   bash /opt/fula-api/scripts/admin-recover-all-buckets.sh --dry-run-only   # preview + tally
#   bash /opt/fula-api/scripts/admin-recover-all-buckets.sh                  # confirm + run
#
# Reads the gateway dump + the pin DB (SELECT); POSTs to the admin endpoint.
# Writes only the log (and nothing outside /tmp). Requires: openssl, curl, jq, docker.

set -euo pipefail

DRY_RUN_ONLY=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --dry-run-only) DRY_RUN_ONLY=1 ;;
        --yes|-y)       ASSUME_YES=1 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | sed 's/^# \{0,1\}//;/^set -/d'
            exit 0 ;;
        *) echo "ERROR: unknown flag '$arg'. Run with -h for help." >&2; exit 2 ;;
    esac
done

if [[ -z "${ADMIN_JWT_SECRET:-}" ]]; then
    echo "ERROR: ADMIN_JWT_SECRET env var is required (source /etc/fula/.env)" >&2
    exit 1
fi
for tool in openssl curl jq docker; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required tool '$tool' not found" >&2; exit 1; }
done

BASE="${FULA_S3:-http://127.0.0.1:9000}"
PG_CONTAINER="${PG_CONTAINER:-postgres-pinning}"
PINNING_TOKEN="${PINNING_TOKEN:-}"
STATUS_EXCLUDE="${STATUS_EXCLUDE:-'deleted','failed'}"
ONLY_BUCKET="${ONLY_BUCKET:-}"
ONLY_OWNER="${ONLY_OWNER:-}"
LOG="${LOG:-/tmp/recover-all-$(date +%s).log}"
REQ_TIMEOUT="${REQ_TIMEOUT:-600}"
RESP="$(mktemp /tmp/recover-all-resp.XXXXXX)"
trap 'rm -f "$RESP"' EXIT

if [[ ! "$STATUS_EXCLUDE" =~ ^\'[a-z]+\'(,\'[a-z]+\')*$ ]]; then
    echo "ERROR: STATUS_EXCLUDE must look like \"'deleted','failed'\"" >&2; exit 1
fi
if [[ -n "$ONLY_OWNER" && ! "$ONLY_OWNER" =~ ^[0-9a-fA-F]{32}$ ]]; then
    echo "ERROR: ONLY_OWNER must be a 32-hex owner_id" >&2; exit 1
fi

b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }
mint_jwt() {
    local now exp h p sig
    now=$(date +%s); exp=$((now + 300))
    h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)
    p=$(printf '%s' '{"sub":"admin","scope":"admin","iat":'"$now"',"exp":'"$exp"'}' | b64url)
    sig=$(printf '%s' "$h.$p" | openssl dgst -sha256 -mac HMAC -macopt "key:$ADMIN_JWT_SECRET" -binary | b64url)
    printf '%s.%s.%s' "$h" "$p" "$sig"
}
psql_q() { docker exec -i "$PG_CONTAINER" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA'; }

valid_hex32() { [[ "$1" =~ ^[0-9a-fA-F]{32}$ ]]; }
valid_bucket() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,62}$ ]]; }
valid_cid()    { [[ "$1" =~ ^[a-zA-Z0-9]{20,120}$ ]]; }
valid_uid()    { [[ "$1" =~ ^([0-9a-f]{32}|[0-9a-f]{64})$ ]]; }  # 32-hex seed OR 64-hex sha256

# ── 1. Pull the gateway bucket dump (owner_id, bucket, root_cid, manifest) ────
echo "===== fetching gateway bucket dump =====" >&2
if ! DUMP=$(curl -sS --max-time 120 -H "Authorization: Bearer $(mint_jwt)" "$BASE/admin/buckets"); then
    echo "ERROR: GET $BASE/admin/buckets failed (gateway up? FULA_ADMIN_API=true? admin secret right?)" >&2
    exit 1
fi
if ! echo "$DUMP" | jq -e '.buckets' >/dev/null 2>&1; then
    echo "ERROR: /admin/buckets did not return the expected JSON. First 300 bytes:" >&2
    echo "${DUMP:0:300}" >&2
    exit 1
fi
TOTAL=$(echo "$DUMP" | jq '.buckets | length')
echo "Gateway knows $TOTAL bucket(s)." >&2
echo "endpoint=$BASE  status-cut=NOT IN (${STATUS_EXCLUDE})  pinning-tok=$([[ -n "$PINNING_TOKEN" ]] && echo present || echo none)  log=$LOG" >&2

if [[ "$DRY_RUN_ONLY" != "1" && "$ASSUME_YES" != "1" ]]; then
    read -r -p "Attempt recovery of up to $TOTAL bucket(s), force=false (only hard-loss mutate)? [type 'yes'] " ans
    [[ "$ans" == "yes" ]] || { echo "Aborted." >&2; exit 1; }
fi

: > "$LOG"
declare -A TALLY=([200]=0 [404]=0 [412]=0 [503]=0 [nobridge]=0 [ambiguous]=0 [noentries]=0 [skip]=0 [other]=0)

# Stream the dump as TSV: owner_id<TAB>bucket<TAB>root_cid<TAB>forest_manifest_cid
mapfile -t ROWS < <(echo "$DUMP" | jq -r '.buckets[] | [.owner_id, .bucket, .root_cid, (.forest_manifest_cid // "")] | @tsv')

i=0
for row in "${ROWS[@]}"; do
    i=$((i+1))
    IFS=$'\t' read -r owner bucket root manifest <<<"$row"

    [[ -n "$ONLY_OWNER"  && "$owner"  != "$ONLY_OWNER"  ]] && continue
    [[ -n "$ONLY_BUCKET" && "$bucket" != "$ONLY_BUCKET" ]] && continue

    if ! valid_hex32 "$owner" || ! valid_bucket "$bucket" || ! valid_cid "$root"; then
        echo "[$i/$TOTAL] SKIP malformed row: owner=$owner bucket=$bucket" | tee -a "$LOG" >&2
        TALLY[skip]=$((TALLY[skip]+1)); continue
    fi
    # Bridge: find THE pinning user for this bucket via content CIDs present on
    # both sides. The root_cid is matched ONLY against THIS bucket's own
    # `bucket:<bucket>` pin — an empty/shared prolly root (every empty bucket has
    # the SAME content-addressed root, computed before the owner is attached)
    # would otherwise collide across users. The forest_manifest_cid is
    # content-unique per bucket (encrypted, salted) so it's matched unscoped.
    # REFUSE if >1 distinct user resolves: the true owner's pin row always
    # survives gc (gc drops blocks, not pin rows), so exactly-1 = the owner and
    # >1 means a collision that must NEVER silently pick a user and rebuild a
    # bucket from someone else's objects (advisor review — blocking).
    bridge_where="(cid='$root' AND name='bucket:$bucket')"
    if [[ -n "$manifest" ]] && valid_cid "$manifest"; then
        bridge_where="$bridge_where OR cid='$manifest'"
    fi
    if ! bridge_out=$(printf "SELECT DISTINCT user_id FROM pins WHERE user_id <> '' AND (%s);" "$bridge_where" | psql_q); then
        echo "[$i/$TOTAL] $bucket  BRIDGE-QUERY-FAILED  skip" | tee -a "$LOG" >&2
        TALLY[other]=$((TALLY[other]+1)); continue
    fi
    mapfile -t uids < <(printf '%s\n' "$bridge_out" | sed '/^$/d')
    if [[ "${#uids[@]}" -eq 0 ]]; then
        echo "[$i/$TOTAL] ${owner:0:10}…/$bucket  NO-BRIDGE (root/manifest not in pin DB)  skip" | tee -a "$LOG"
        TALLY[nobridge]=$((TALLY[nobridge]+1)); continue
    fi
    if [[ "${#uids[@]}" -gt 1 ]]; then
        echo "[$i/$TOTAL] ${owner:0:10}…/$bucket  AMBIGUOUS-BRIDGE (${#uids[@]} users — refusing, no silent wrong-pick)  skip" | tee -a "$LOG"
        TALLY[ambiguous]=$((TALLY[ambiguous]+1)); continue
    fi
    uid="${uids[0]}"
    if ! valid_uid "$uid"; then
        echo "[$i/$TOTAL] $bucket  BAD-UID($uid)  skip" | tee -a "$LOG" >&2
        TALLY[other]=$((TALLY[other]+1)); continue
    fi

    # Entries for (uid, bucket): current pin per key (DISTINCT ON) — object pins
    # (prefix stripped) UNION the user's forest nodes (name IS the key).
    if ! entries=$(printf "SELECT coalesce(json_agg(json_build_object('key',k,'cid',cid,'size',size)),'[]'::json) FROM (
        SELECT DISTINCT ON (k) k, cid, size FROM (
            SELECT substr(name, length('object:%s/')+1) AS k, cid, size, updated_at
              FROM pins WHERE user_id='%s' AND starts_with(name,'object:%s/') AND status NOT IN (%s)
            UNION ALL
            SELECT name AS k, cid, size, updated_at
              FROM pins WHERE user_id='%s' AND starts_with(name,'__fula_forest_') AND status NOT IN (%s)
        ) u ORDER BY k, updated_at DESC) e;" \
        "$bucket" "$uid" "$bucket" "$STATUS_EXCLUDE" "$uid" "$STATUS_EXCLUDE" | psql_q); then
        echo "[$i/$TOTAL] $bucket  ENTRIES-QUERY-FAILED  skip" | tee -a "$LOG" >&2
        TALLY[other]=$((TALLY[other]+1)); continue
    fi
    n=$(jq 'length' <<<"$entries" 2>/dev/null || echo 0)

    if [[ "$DRY_RUN_ONLY" == "1" ]]; then
        printf '[%d/%d] %s/%s  owner=%s  uid=%s  entries=%s\n' \
            "$i" "$TOTAL" "${owner:0:10}…" "$bucket" "${owner:0:10}…" "${uid:0:10}…" "$n" | tee -a "$LOG"
        continue
    fi
    if [[ "$n" -eq 0 ]]; then
        echo "[$i/$TOTAL] $bucket  NO-ENTRIES  skip" | tee -a "$LOG" >&2
        TALLY[noentries]=$((TALLY[noentries]+1)); continue
    fi

    # POST with the pre-hashed owner_id (no email, no hash_user_id on the server).
    payload=$(jq -nc --arg o "$owner" --arg b "$bucket" --argjson e "$entries" \
        '{owner_id:$o, bucket:$b, force:false, entries:$e}')
    hdrs=(-H "Authorization: Bearer $(mint_jwt)" -H "Content-Type: application/json")
    [[ -n "$PINNING_TOKEN" ]] && hdrs+=(-H "X-Pinning-Token: $PINNING_TOKEN")
    : > "$RESP"
    code=$(curl -sS -o "$RESP" -w '%{http_code}' --max-time "$REQ_TIMEOUT" \
        -X POST "${hdrs[@]}" --data-binary @- "$BASE/admin/recover-bucket-index" <<<"$payload") || code="000"

    summary=$(jq -rc '{new_root,entry_count,index_nodes_pinned}' "$RESP" 2>/dev/null || true)
    case "$code" in
        200) TALLY[200]=$((TALLY[200]+1)); tag="REBUILT" ;;
        412) TALLY[412]=$((TALLY[412]+1)); tag="skip-healthy" ;;
        404) TALLY[404]=$((TALLY[404]+1)); tag="owner/bucket-miss" ;;
        503) TALLY[503]=$((TALLY[503]+1)); tag="inconclusive-retry" ;;
        *)   TALLY[other]=$((TALLY[other]+1)); tag="HTTP-$code" ;;
    esac
    printf '[%d/%d] %s/%s  n=%s  %s  %s\n' "$i" "$TOTAL" "${owner:0:10}…" "$bucket" "$n" "$tag" "$summary" | tee -a "$LOG"
done

echo "" >&2
echo "===== summary =====" | tee -a "$LOG" >&2
printf '  rebuilt(200)        : %s\n' "${TALLY[200]}"      | tee -a "$LOG"
printf '  skip-healthy(412)   : %s\n' "${TALLY[412]}"      | tee -a "$LOG"
printf '  owner/bucket-miss   : %s\n' "${TALLY[404]}"      | tee -a "$LOG"
printf '  inconclusive(503)   : %s\n' "${TALLY[503]}"      | tee -a "$LOG"
printf '  no-bridge           : %s\n' "${TALLY[nobridge]}" | tee -a "$LOG"
printf '  ambiguous-refused   : %s\n' "${TALLY[ambiguous]}"| tee -a "$LOG"
printf '  no-entries          : %s\n' "${TALLY[noentries]}"| tee -a "$LOG"
printf '  malformed-skip      : %s\n' "${TALLY[skip]}"     | tee -a "$LOG"
printf '  other               : %s\n' "${TALLY[other]}"    | tee -a "$LOG"
echo "Full per-bucket log: $LOG" >&2
