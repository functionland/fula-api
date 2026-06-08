# Local-retain replication migration + GC-safety runbook

How to (1) replicate the legacy un-replicated backlog (~105 GB) to the cluster
and (2) reach a state where `ipfs repo gc` is provably safe to run periodically
on the master — without ever losing un-replicated data, and without replicating
transient IPFS-network cache.

> **Audience:** the gateway operator (you). Every state-changing command here is
> run by you on the master. The code changes referenced are in `fula-cli`
> (`local_retain.rs`, `local_retain_queue.rs`, `ipfs.rs`, `object.rs`,
> `multipart.rs`, `server.rs`).

---

## What changed (why this is now safe)

* **The verifier RE-DRIVES cluster pins** for under-replicated backlog blocks
  (`process_one` → `RetainAction::KeepAndRedrive`). This is what actually
  replicates blocks whose original cluster pin never landed — the missing piece
  that left the backlog stuck.
* **Whole-backlog sweep** via a persistent cursor (`list_from`) — no head-of-line
  stall, and one permanently-stuck block can't block the rest.
* **Drop only when confirmed** on `>= min_repl` (=2) **non-master** holders
  (`decide`), with an `auto_drop` switch so the migration can replicate WITHOUT
  dropping until you've audited.
* **Large-object leaves protected without a blanket backfill** — the PUT path
  uses `retain_with_leaves` (direct-pin the dag-pb root + its raw leaves, track
  the root). So only Fula data is ever pinned; transient network cache never is.
* **`refs local` backfill default → OFF** (it pinned *everything* local,
  including cache). New Fula data is protected by the PUT path instead.

**The GC-safety invariant:** a block is locally pinned **iff** it is Fula data
awaiting/holding replication. `ipfs repo gc` can therefore only ever remove
network cache + Fula data already confirmed on `>= 2` non-master holders. It can
never remove un-replicated Fula data.

---

## Config knobs (env on the gateway)

| Env | Default | Meaning |
|---|---|---|
| `FULA_LOCAL_RETAIN_REDRIVE` | `true` | Verifier re-drives a cluster pin for under-replicated backlog blocks. Set `false` to pause re-drives (re-assert-only). |
| `FULA_LOCAL_RETAIN_AUTO_DROP` | `true` | Verifier drops the master's local copy once `>=2` non-master holders confirm. **Set `false` for the supervised migration (replicate-only — never unpins).** |
| `FULA_LOCAL_RETAIN_SETTLE_SECS` | `300` | A block must hold `>=2` non-master holders for **this long** before the master drops its copy — absorbs eventually-consistent cluster status so an unsupervised drop never fires on a single transient/stale "pinned". Set `0` for an already-audited legacy drain (drop as soon as confirmed). |
| `FULA_NO_LOCAL_RETAIN_BACKFILL` | (keep set) | Disables the `refs local` backfill (now default-off anyway). Keep it set. |
| `local_retain_interval_secs` | (config) | Verifier cycle interval — the drain pace knob (min 15s). |

The verifier processes up to **256 blocks/cycle** (8 concurrent). Two guards on
the irreversible *drop*: (a) a **settle** — replication must be confirmed for
`SETTLE_SECS` before unpinning; (b) the **breaker** — after **20 consecutive**
cluster-API failures, the verifier neither re-drives NOR drops (it only
re-asserts local pins, keeping blocks gc-safe), so it never deletes the only
complete copy while the cluster's own health signal is flaky.

---

## Migration procedure

### Step 0 — Prerequisites (read-only checks)

1. **Cluster has enough healthy holders** (need `>= min_repl` reachable, non-master):
   ```
   docker exec ipfs_cluster ipfs-cluster-ctl peers ls | grep -c '^12D3'
   ```
2. **Pin pipeline not backed up** (PIN_ERROR / PINNING small):
   ```
   docker exec ipfs_cluster ipfs-cluster-ctl status --filter pin_error | grep -c ':'
   ```
   Remove/repair any persistently-dead holders first (CRDT cluster: dead peers
   drop out automatically, but EXISTING stuck allocations don't auto-reallocate —
   re-pin those roots or remove the dead peer so the baseline error count is ~0).
3. **Master can serve blocks to holders:**
   ```
   docker exec ipfs_host ipfs bitswap stat | grep 'blocks sent'
   ```
4. **Peer RAM headroom** — the migration adds ~840k individual pins (→ ~1.2M
   total). ipfs-cluster handles this, but confirm peers aren't RAM-constrained,
   and prefer `pin ls` (shared state) over full `status` scans when monitoring.

### Step 1 — Canary (built into the replicate-only start)

Deploy with **`FULA_LOCAL_RETAIN_AUTO_DROP=false`** and `FULA_LOCAL_RETAIN_REDRIVE=true`.
The verifier begins re-driving the backlog (replicating) but **drops nothing**.

Watch the **first ~1,000 blocks** (first few cycles) actually reach `>=2`
non-master holders before letting it run unattended. Sample backlog CIDs and
check their cluster status; if they are NOT replicating (stuck PINNING / dial
errors), **STOP** and fix holder health / the master's provider path first — a
backlog that won't replicate at 1k won't replicate at 840k.

### Step 2 — Replicate-only drain

Let the verifier run replicate-only (`auto_drop=false`). Over many cycles it
re-drives every backlog block. Monitor **replication progress** (not backlog
size — nothing is removed yet):

* cluster pinned-count growing (`ipfs-cluster-ctl status --filter pinned`), and
* a rolling sample of backlog CIDs reaching `>=2` non-master holders.

Pace with `local_retain_interval_secs` if the cluster shows strain. The breaker
auto-pauses re-drives if the cluster API starts failing.

### Step 3 — Audit BEFORE any drop (the irreversible step)

Before enabling drops, **independently verify** a random sample of
replicated-looking blocks really exist on `>=2` non-master holders — not just
that the cluster *reports* "pinned" (a control-plane assertion can be stale).
For a raw block, presence == correctness (content-addressed), so fetching it
from a holder and confirming it hashes to its CID is decisive.

If the audit fails → keep `auto_drop=false`, investigate. Do not drop.

### Step 4 — Enable drops (reclaim ~105 GB)

Set **`FULA_LOCAL_RETAIN_AUTO_DROP=true`**. The verifier now drops each block
confirmed on `>=2` non-master holders (and, for large-object roots, drops their
leaves too) — each one `SETTLE_SECS` after its replication is first confirmed.
Because you already audited the legacy set in Step 3, you may set
**`FULA_LOCAL_RETAIN_SETTLE_SECS=0`** for the legacy drain so confirmed blocks
drop immediately (faster reclaim); restore the default (300) for steady state.
Monitor:

* `local-retain backlog status` log lines — `pending` should trend **down**;
* master `ipfs repo stat` RepoSize trending **down**.

### Step 5 — Pre-GC health check

Before the FIRST `ipfs repo gc`:

1. Backlog `pending` ≈ 0 (or only genuinely-stuck blocks you've investigated).
2. Spot-check ~100 dropped CIDs: each still `>=2` non-master holders.
3. Cluster PIN_ERROR ≈ 0.

### Step 6 — Periodic GC

`ipfs repo gc` is now safe to run on a schedule: it can only reclaim network
cache + already-replicated Fula data. Keep `FULA_NO_LOCAL_RETAIN_BACKFILL` set
and `auto_drop=true` for steady state.

---

## Rollback / safety

* **Pause everything:** `FULA_LOCAL_RETAIN_REDRIVE=false` + `FULA_LOCAL_RETAIN_AUTO_DROP=false`
  → the verifier only re-asserts local pins (no new replication, no drops).
  Nothing is ever lost: a local copy is dropped ONLY after `>=2` non-master
  holders confirm.
* **Do not run `ipfs repo gc` while `auto_drop=false`** mid-migration unless the
  backlog is intact — the local pins are the only thing protecting un-replicated
  blocks until they replicate.
* The 5 known stuck roots are **pre-existing partial loss** (gc'd leaves, ~12%
  missing) — they will never fully replicate (the data is gone) and are out of
  scope for this migration; their *present* leaves replicate with everything else.

---

## Notes on scope

* This drains the **existing** ~839,830-block backlog via per-block re-drive
  (those leaves' roots are gc'd, so there's no root to track — the ~840k
  individual-pin path). Going-forward large objects use `retain_with_leaves`
  (root-tracked, no per-leaf cluster pins), so the bloat does not recur.
* "Replicate as-is" decision (operator): the legacy backlog is replicated
  without a Fula-format filter — every sample inspected was Fula data
  (encrypted UnixFS leaves + prolly-tree nodes) on a private cluster.
