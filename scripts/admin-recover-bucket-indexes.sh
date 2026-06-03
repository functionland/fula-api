#!/usr/bin/env bash
# admin-recover-bucket-indexes.sh — rebuild HARD-LOSS bucket indexes server-side
# from the pinning Postgres DB, via POST /admin/recover-bucket-index.
#
# WHY ───────────────────────────────────────────────────────────────────────
#   A bucket's S3 object index is a ProllyTree persisted as dag-cbor blocks
#   whose child CIDs serialize as CBOR *strings*, not IPLD links — so
#   ipfs-cluster recursive pins cover only the root block and `ipfs repo gc`
#   reclaims every interior/leaf node. The bucket root then no longer walks and
#   S3 LIST returns 410 ("hard loss"). The OBJECTS themselves still exist in the
#   pinning DB as pins named `object:<bucket>/<key>` (+ the encrypted-forest
#   nodes as `__fula_forest_*`). This script rebuilds each lost index from those
#   pins and re-pins the rebuilt nodes (gc-safe) so the bucket lists again.
#
#   The endpoint is SELF-SELECTING and SAFE: with force=false it probes each
#   bucket and only rebuilds genuine hard-loss ones —
#     200  rebuilt          (was hard-loss)
#     412  skipped-healthy  (still walkable / cluster-recoverable; re-pin, don't
#                            rebuild — the gateway's startup index-pin backfill
#                            handles these)
#     404  no-such-bucket   (identity didn't match a bucket — see IDENTITY)
#     503  inconclusive     (transient probe failure — safe to re-run)
#   Only (hard-loss + correct identity) ever mutates anything, so you can run
#   this broadly and read the per-bucket outcome from the log.
#
# IDENTITY ───────────────────────────────────────────────────────────────────
#   The gateway keys buckets by hash_user_id(JWT-sub). Two user classes:
#     • SEED users (Mode B/C): pins.user_id is the 32-hex effective_user_id,
#       which IS the JWT sub. Pass it directly — handled automatically.
#     • OAuth users: pins.user_id is sha256(lower(email)) (64-hex), but the
#       bucket key is hash_user_id(EMAIL) — a different hash of the same email.
#       sha256(email) is one-way and the plaintext email is NOT stored in the
#       pin DB (webui_users.email is empty; encrypted_email is AES-GCM under the
#       pinning-service ENCRYPTION_KEY). So OAuth buckets need the plaintext
#       email. Supply it via EMAIL_CSV (see below); without it, OAuth buckets
#       404 here and are instead recovered app-side (the live app has the email
#       in its JWT). Seed users do not need EMAIL_CSV.
#
#   Strategy per (user_id, bucket): POST with identity = pins.user_id first; on
#   404, if EMAIL_CSV maps that user_id to an email, retry with the email. The
#   per-bucket log shows which identity matched. RUN THE CANARY FIRST (below) to
#   learn, empirically, which identity your fleet uses before the full sweep.
#
# REQUIRED env ───────────────────────────────────────────────────────────────
#   ADMIN_JWT_SECRET   The HS256 admin secret from /etc/fula/.env on master.
#                      The script mints its own short-lived admin JWT from it.
#                      (The gateway must also have FULA_ADMIN_API=true.)
#
# OPTIONAL env ───────────────────────────────────────────────────────────────
#   FULA_S3            Gateway base URL. Default http://127.0.0.1:9000 (master).
#   PG_CONTAINER       Pinning Postgres container. Default postgres-pinning.
#   PINNING_TOKEN      Pinning JWT for cluster-replicating the rebuilt nodes +
#                      new registry root. OPTIONAL — empty uses the no-token
#                      persist path, which still heals registry.cid and locally
#                      pins the rebuilt index (gc-safe on master); only off-box
#                      replication is then best-effort. Leave empty for recovery.
#   EMAIL_CSV          Path to a `user_id,email` CSV (64-hex pins.user_id →
#                      plaintext email) for OAuth users. Build it by decrypting
#                      webui_users.encrypted_email with the pinning-service
#                      ENCRYPTION_KEY, or export from your OAuth provider.
#   STATUS_EXCLUDE     Pin statuses to EXCLUDE from the rebuilt index. Default
#                      'deleted','failed' (failed = upload never completed → a
#                      dangling index entry). Set to 'deleted' alone to be
#                      maximally inclusive.
#   ONLY_USER          Canary/scope: restrict to this pins.user_id.
#   ONLY_BUCKET        Canary/scope: restrict to this bucket name.
#   LOG                Per-bucket outcome log. Default /tmp/recover-<epoch>.log
#
# FLAGS ───────────────────────────────────────────────────────────────────────
#   --dry-run-only   Enumerate targets + entry counts; POST nothing.
#   --yes | -y       Skip the pre-sweep confirmation prompt.
#   -h | --help      Show this header.
#
# CANARY-FIRST (strongly recommended) ─────────────────────────────────────────
#   Validate the whole identity→hash→bucket-key→rebuild pipeline on ONE known
#   bucket before the fleet sweep. This is the FIRST real end-to-end test of the
#   whole chain (probe → pin-before-commit → root swap → client LIST) — expect to
#   verify/debug here, NOT to rubber-stamp. Prereqs: the gateway is deployed with
#   the recovery endpoint AND FULA_ADMIN_API=true (a 403 means it isn't enabled).
#
#   For a SEED canary user (32-hex pins.user_id) — identity is automatic:
#     export ADMIN_JWT_SECRET="<from /etc/fula/.env>"
#     ONLY_USER="<32-hex pins.user_id>" ONLY_BUCKET="images" \
#       ./scripts/admin-recover-bucket-indexes.sh --yes
#
#   For an OAUTH canary user (64-hex pins.user_id) you MUST supply the email, or
#   it 404s (the bucket is keyed by hash_user_id(EMAIL), not hash_user_id(uid)):
#     printf '%s,%s\n' "<64-hex pins.user_id>" "<plaintext-email>" > /tmp/canary.csv
#     export ADMIN_JWT_SECRET="<from /etc/fula/.env>"
#     EMAIL_CSV=/tmp/canary.csv ONLY_USER="<64-hex>" ONLY_BUCKET="images" \
#       ./scripts/admin-recover-bucket-indexes.sh --yes
#   The log shows `id=email` when the email path matched. A 200 + the user's
#   client successfully LISTing the bucket = the pipeline works; THEN sweep.
#   (No PINNING_TOKEN needed — recovery heals registry.cid via the same no-token
#   persist path admin-pii-sweep.sh already uses in production.)
#
# FULL SWEEP ───────────────────────────────────────────────────────────────────
#     export ADMIN_JWT_SECRET="<from /etc/fula/.env>"
#     # optional: export EMAIL_CSV=/tmp/user_emails.csv   # for OAuth users
#     ./scripts/admin-recover-bucket-indexes.sh --dry-run-only   # preview
#     ./scripts/admin-recover-bucket-indexes.sh                  # confirm + run
#
# Reads only the pin DB (SELECT) + POSTs to the admin endpoint. Writes only the
# log + nothing else outside /tmp. Requires: openssl, curl, jq, docker.

set -euo pipefail

DRY_RUN_ONLY=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --dry-run-only) DRY_RUN_ONLY=1 ;;
        --yes|-y)       ASSUME_YES=1 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | sed 's/^# \{0,1\}//;/^set -/d'
            exit 0
            ;;
        *) echo "ERROR: unknown flag '$arg'. Run with -h for help." >&2; exit 2 ;;
    esac
done

if [[ -z "${ADMIN_JWT_SECRET:-}" ]]; then
    echo "ERROR: ADMIN_JWT_SECRET env var is required (source /etc/fula/.env)" >&2
    exit 1
fi
for tool in openssl curl jq docker; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

BASE="${FULA_S3:-http://127.0.0.1:9000}"
PG_CONTAINER="${PG_CONTAINER:-postgres-pinning}"
PINNING_TOKEN="${PINNING_TOKEN:-}"
EMAIL_CSV="${EMAIL_CSV:-}"
STATUS_EXCLUDE="${STATUS_EXCLUDE:-'deleted','failed'}"
ONLY_USER="${ONLY_USER:-}"
ONLY_BUCKET="${ONLY_BUCKET:-}"
LOG="${LOG:-/tmp/recover-$(date +%s).log}"
REQ_TIMEOUT="${REQ_TIMEOUT:-600}"
RESP="$(mktemp /tmp/recover-resp.XXXXXX)"
trap 'rm -f "$RESP"' EXIT

b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }

# Mint a short-lived admin JWT (sub=admin, scope=admin) — same scheme as
# admin-pii-sweep.sh. Minted fresh per request so a slow sweep can't outlive it.
mint_jwt() {
    local now exp header payload h p signing_input sig
    now=$(date +%s); exp=$((now + 300))
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

# Run a SQL statement against the pinning DB. Credentials stay inside the
# container (referenced as $POSTGRES_USER/$POSTGRES_DB by the container shell —
# never printed). -tA = tuples-only, unaligned.
psql_q() { docker exec -i "$PG_CONTAINER" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA'; }

# Validate identifiers we interpolate into SQL (defence-in-depth; S3 bucket
# names and hex user_ids can't legally contain quotes anyway).
valid_uid()    { [[ "$1" =~ ^[0-9a-fA-F]{32,64}$ ]]; }
valid_bucket() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,62}$ ]]; }

# Validate operator-supplied SQL fragments BEFORE interpolation. (uid/bucket
# coming from the DB are re-checked per-row in the loop; these env values are
# otherwise unguarded and go straight into SQL — codex review.)
if [[ -n "$ONLY_USER" ]] && ! valid_uid "$ONLY_USER"; then
    echo "ERROR: ONLY_USER must be a 32/64-hex id" >&2; exit 1
fi
if [[ -n "$ONLY_BUCKET" ]] && ! valid_bucket "$ONLY_BUCKET"; then
    echo "ERROR: ONLY_BUCKET must be a valid bucket name" >&2; exit 1
fi
if [[ ! "$STATUS_EXCLUDE" =~ ^\'[a-z]+\'(,\'[a-z]+\')*$ ]]; then
    echo "ERROR: STATUS_EXCLUDE must look like \"'deleted','failed'\" (quoted, comma-separated)" >&2; exit 1
fi

# Load EMAIL_CSV (user_id,email) into an assoc array for the OAuth fallback.
declare -A USER_EMAIL=()
if [[ -n "$EMAIL_CSV" ]]; then
    if [[ ! -r "$EMAIL_CSV" ]]; then
        echo "ERROR: EMAIL_CSV '$EMAIL_CSV' not readable" >&2; exit 1
    fi
    while IFS=, read -r u e; do
        u="${u//[$'\r\n\t ']/}"; e="${e//[$'\r\n ']/}"
        [[ -z "$u" || -z "$e" || "$u" == "user_id" ]] && continue
        USER_EMAIL["$u"]="$e"
    done < "$EMAIL_CSV"
    echo "Loaded ${#USER_EMAIL[@]} user_id→email mapping(s) from $EMAIL_CSV" >&2
fi

# ── Enumerate target (user_id, bucket) pairs from the object pins ────────────
echo "===== enumerating buckets from the pin DB =====" >&2
ENUM_SQL="SELECT DISTINCT user_id || '|' || split_part(substr(name,8),'/',1)
          FROM pins
          WHERE name LIKE 'object:%' AND status NOT IN (${STATUS_EXCLUDE})"
if [[ -n "$ONLY_USER" ]];   then ENUM_SQL="$ENUM_SQL AND user_id = '${ONLY_USER}'"; fi
if [[ -n "$ONLY_BUCKET" ]]; then ENUM_SQL="$ENUM_SQL AND split_part(substr(name,8),'/',1) = '${ONLY_BUCKET}'"; fi
ENUM_SQL="$ENUM_SQL ORDER BY 1;"

# Capture explicitly: a process-substitution `< <(psql_q)` would swallow a
# psql/docker failure under set -e and look like "0 candidates" — codex review.
if ! ENUM_OUT=$(printf '%s' "$ENUM_SQL" | psql_q); then
    echo "ERROR: enumeration query failed (psql/docker). Aborting — this is NOT 'nothing to do'." >&2
    exit 1
fi
mapfile -t PAIRS < <(printf '%s\n' "$ENUM_OUT" | sed '/^$/d')
echo "Found ${#PAIRS[@]} (user, bucket) candidate(s)." >&2
if [[ "${#PAIRS[@]}" -eq 0 ]]; then echo "Nothing to do." >&2; exit 0; fi

# Build the entries JSON array for one (uid, bucket): the bucket-scoped object
# pins (key = name minus the `object:<bucket>/` prefix) UNION the user's
# encrypted-forest nodes (name IS the S3 key; user-wide, so included in every
# one of that user's buckets — harmless extras the client never requests).
entries_json() {
    local uid="$1" bucket="$2"
    # starts_with() (not LIKE) so a `_` in a bucket name is a literal, not a
    # wildcard. DISTINCT ON (k) ORDER BY updated_at DESC keeps the CURRENT pin
    # per key (a re-uploaded object has multiple pins) so the rebuild is
    # deterministic — codex review.
    printf "SELECT coalesce(json_agg(json_build_object('key',k,'cid',cid,'size',size)),'[]'::json) FROM (
        SELECT DISTINCT ON (k) k, cid, size FROM (
            SELECT substr(name, length('object:%s/')+1) AS k, cid, size, updated_at
              FROM pins WHERE user_id='%s' AND starts_with(name,'object:%s/') AND status NOT IN (%s)
            UNION ALL
            SELECT name AS k, cid, size, updated_at
              FROM pins WHERE user_id='%s' AND starts_with(name,'__fula_forest_') AND status NOT IN (%s)
        ) u ORDER BY k, updated_at DESC
    ) e;" "$bucket" "$uid" "$bucket" "$STATUS_EXCLUDE" "$uid" "$STATUS_EXCLUDE" | psql_q
}

# POST one recovery request; echoes the HTTP status code.
post_recover() {
    local identity="$1" bucket="$2" entries="$3" jwt payload code
    jwt=$(mint_jwt)
    payload=$(jq -nc --arg uid "$identity" --arg b "$bucket" --argjson e "$entries" \
        '{user_id:$uid, bucket:$b, force:false, entries:$e}')
    local hdrs=(-H "Authorization: Bearer $jwt" -H "Content-Type: application/json")
    [[ -n "$PINNING_TOKEN" ]] && hdrs+=(-H "X-Pinning-Token: $PINNING_TOKEN")
    : > "$RESP"
    # Capture the status exactly once (a bare `curl … || echo 000` can emit
    # `000000` on connect failure) — codex review.
    code=$(curl -sS -o "$RESP" -w '%{http_code}' --max-time "$REQ_TIMEOUT" \
        -X POST "${hdrs[@]}" --data-binary @- \
        "$BASE/admin/recover-bucket-index" <<<"$payload") || code="000"
    echo "$code"
}

echo "" >&2
echo "endpoint   = $BASE/admin/recover-bucket-index" >&2
echo "status-cut = NOT IN (${STATUS_EXCLUDE})" >&2
echo "pinning-tok= $([[ -n "$PINNING_TOKEN" ]] && echo present || echo '(empty → no-token heal)')" >&2
echo "log        = $LOG" >&2
echo "" >&2

if [[ "$DRY_RUN_ONLY" != "1" && "$ASSUME_YES" != "1" ]]; then
    read -r -p "Recover ${#PAIRS[@]} bucket(s) with force=false (only hard-loss mutate)? [type 'yes'] " ans
    [[ "$ans" == "yes" ]] || { echo "Aborted." >&2; exit 1; }
fi

: > "$LOG"
declare -A TALLY=([200]=0 [404]=0 [412]=0 [503]=0 [skip]=0 [other]=0)
i=0
for pair in "${PAIRS[@]}"; do
    i=$((i+1))
    uid="${pair%%|*}"; bucket="${pair#*|}"
    if ! valid_uid "$uid" || ! valid_bucket "$bucket"; then
        echo "[$i/${#PAIRS[@]}] SKIP malformed pair: $pair" | tee -a "$LOG" >&2
        TALLY[skip]=$((TALLY[skip]+1)); continue
    fi

    # One bucket's transient psql failure must not abort the whole sweep
    # (set -e would exit on the bare command substitution) — codex review.
    if ! entries=$(entries_json "$uid" "$bucket"); then
        echo "[$i/${#PAIRS[@]}] $bucket  ENTRIES-QUERY-FAILED  skip" | tee -a "$LOG" >&2
        TALLY[other]=$((TALLY[other]+1)); continue
    fi
    n=$(jq 'length' <<<"$entries" 2>/dev/null || echo 0)

    if [[ "$DRY_RUN_ONLY" == "1" ]]; then
        email="${USER_EMAIL[$uid]:-}"
        printf '[%d/%d] %s/%s  entries=%s  identity=%s%s\n' \
            "$i" "${#PAIRS[@]}" "${uid:0:12}…" "$bucket" "$n" \
            "$([[ ${#uid} -eq 32 ]] && echo seed:uid || echo uid)" \
            "$([[ -n "$email" ]] && echo '(+email-fallback)' || true)" | tee -a "$LOG"
        continue
    fi

    if [[ "$n" -eq 0 ]]; then
        echo "[$i/${#PAIRS[@]}] $bucket  no-entries  SKIP" | tee -a "$LOG" >&2
        TALLY[skip]=$((TALLY[skip]+1)); continue
    fi

    # Attempt 1: identity = pins.user_id (works for seed always; OAuth iff the
    # bucket was keyed by hash_user_id(sha256(email))).
    code=$(post_recover "$uid" "$bucket" "$entries")
    used="uid"
    # Attempt 2 (OAuth fallback): on 404, retry with the plaintext email.
    if [[ "$code" == "404" && -n "${USER_EMAIL[$uid]:-}" ]]; then
        code=$(post_recover "${USER_EMAIL[$uid]}" "$bucket" "$entries")
        used="email"
    fi

    summary=$(jq -rc '{new_root,entry_count,index_nodes_pinned,skipped_count}' "$RESP" 2>/dev/null || cat "$RESP" 2>/dev/null)
    case "$code" in
        200) TALLY[200]=$((TALLY[200]+1)); tag="REBUILT" ;;
        412) TALLY[412]=$((TALLY[412]+1)); tag="skip-healthy" ;;
        404) TALLY[404]=$((TALLY[404]+1)); tag="no-such-bucket" ;;
        503) TALLY[503]=$((TALLY[503]+1)); tag="inconclusive-retry" ;;
        *)   TALLY[other]=$((TALLY[other]+1)); tag="HTTP-$code" ;;
    esac
    printf '[%d/%d] %s/%s  n=%s  id=%s  %s  %s\n' \
        "$i" "${#PAIRS[@]}" "${uid:0:12}…" "$bucket" "$n" "$used" "$tag" "$summary" | tee -a "$LOG"
done

echo "" >&2
echo "===== summary =====" | tee -a "$LOG" >&2
printf '  rebuilt(200)        : %s\n' "${TALLY[200]}"   | tee -a "$LOG"
printf '  skip-healthy(412)   : %s\n' "${TALLY[412]}"   | tee -a "$LOG"
printf '  no-such-bucket(404) : %s\n' "${TALLY[404]}"   | tee -a "$LOG"
printf '  inconclusive(503)   : %s\n' "${TALLY[503]}"   | tee -a "$LOG"
printf '  skipped/empty       : %s\n' "${TALLY[skip]}"  | tee -a "$LOG"
printf '  other               : %s\n' "${TALLY[other]}" | tee -a "$LOG"
echo "Full per-bucket log: $LOG" >&2
if [[ "${TALLY[404]}" -gt 0 && -z "$EMAIL_CSV" ]]; then
    echo "" >&2
    echo "NOTE: ${TALLY[404]} bucket(s) 404'd. If these are OAuth users, supply EMAIL_CSV" >&2
    echo "      (user_id,email) and re-run — or recover them app-side (P4)." >&2
fi
