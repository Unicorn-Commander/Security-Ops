# Scanner-Host Runbook — secops-runner Deployment

**Status:** Pre-GA prototype. Do NOT deploy to production without Aaron approval.

---

## 0. Migration Overview — Colocated → Dedicated

### Current state

The `secops-runner` sidecar (host-root, Docker socket, `network_mode: host`) runs
ON RACKBOY1, co-located with PHI (glitter-mane) and financial production (TPO/AO).
The API also runs on rackboy1 with `SECOPS_RUN_DISPATCH_MODE=queue`.

### Target state

The `secops-runner` sidecar runs on a DEDICATED host (`scanner-1`) that carries NO
other workloads. The API on rackboy1 stays unchanged (still `queue` mode). The
scanner-1 runner polls the same PG database over the tailnet.

### No-downtime property

The API and runner are DECOUPLED by the `run_queue` table. The runner is a
consumer that claims and processes queue entries. The migration is safe at
any point because:

1. **API keeps serving** — the API enqueues runs during and after migration.
   Queue entries accumulate harmlessly if no runner is consuming them.
2. **At most one runner** — the `claim_next` query uses `FOR UPDATE SKIP LOCKED`.
   If two runners (old rackboy1 + new scanner-1) race briefly during transition,
   each will claim distinct queue entries with no double-processing.
3. **No data loss** — the `runs` table is the durable record; `run_queue` is
   ephemeral hand-off metadata. A claimed-but-unprocessed queue entry with no
   runner to process it leaves the run in PENDING status — the operator can
   re-enqueue it.

### Migration sequence (high-level)

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  BEFORE  │ ──────→ │  DURING  │ ──────→ │  AFTER   │
│          │         │          │         │          │
│ rackboy1 │         │ rackboy1 │         │ rackboy1 │
│  secops-api (queue)│  secops-api (queue)│  secops-api (queue)│
│  secops-runner (X) │  [no runner]  │  [no runner]  │
│          │         │          │         │          │
│          │         │ scanner-1│         │ scanner-1│
│          │         │  [deploying]      │  secops-runner (✓)│
└──────────┘         └──────────┘         └──────────┘
```

### Rollback sequence (high-level)

```
┌──────────┐         ┌──────────┐
│  AFTER   │ ──────→ │ ROLLBACK │
│          │         │          │
│ scanner-1│         │ rackboy1 │
│  secops-runner (X) │  secops-runner (✓)│
└──────────┘         └──────────┘
```

No API downtime in either direction. The gap window between stopping one runner
and starting the other means queued runs accumulate — they are processed once
the new runner starts consuming.

---

## 1. Provisioning

```bash
# 1. Install OS (Debian 12 minimal)
# 2. Install Docker CE + Tailscale
apt-get update && apt-get install -y docker-ce tailscale

# 3. Authenticate Tailscale to Headscale
tailscale up --login-server=https://headscale.sarge.ts.net --authkey=<key>

# 4. Verify ACLs
tailscale status                  # scanner-1 visible
tailscale ping rackboy1           # reachable
tailscale ping bigboy             # reachable
```

## 2. Runner Deployment

```bash
# 1. Pull runner image
docker pull ghcr.io/anomalyco/secops-runner:prod

# 2. Create Docker secrets
echo "$SECOPS_APP_PASSWORD" | docker secret create secops_app_password -
echo "$SECOPS_INTERNAL_LITELLM_API_KEY" | docker secret create secops_litellm_key -

# 3. Run container
docker run -d \
  --name secops-runner \
  --restart unless-stopped \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --secret secops_app_password \
  --secret secops_litellm_key \
  -e SECOPS_APP_PASSWORD_FILE=/run/secrets/secops_app_password \
  -e SECOPS_INTERNAL_LITELLM_API_KEY_FILE=/run/secrets/secops_litellm_key \
  -e SECOPS_DB_DSN="postgresql+asyncpg://secops_app@rackboy1:55432/secops" \
  -e SECOPS_LITELLM_BASE_URL="https://bigboy.sarge.ts.net:4000" \
  ghcr.io/anomalyco/secops-runner:prod
```

## 3. Secret Transfer Plan

**Goal:** Deliver `SECOPS_APP_PASSWORD` and `SECOPS_INTERNAL_LITELLM_API_KEY` to
scanner-1 without writing them to disk unencrypted.

| Step | Method | Who |
|------|--------|-----|
| 1 | Generate a one-time Tailscale SSH session to scanner-1 | Aaron |
| 2 | Transfer secret files via `scp` from Aaron's workstation (over Tailscale tunnel) | Aaron |
| 3 | Write to Docker secrets (`docker secret create`) | Aaron |
| 4 | Wipe temporary files (`shred -u`) | Aaron |
| 5 | Verify secrets are readable only via `docker exec secops-runner cat /run/secrets/*` | Aaron |

**No secret leaves Aaron's workstation except encrypted-in-transit via SSH over
Tailscale (WireGuard).** No secret is written to CI, GitHub Actions secrets, or
the runner's config file.

## 4. Day-2 Operations

### Health check
```bash
docker logs secops-runner --tail 20
# Look for: "Runner started, polling run_queue..."

# Check PG connectivity
docker exec secops-runner python -c "
import asyncpg
import asyncio, os
async def check():
    conn = await asyncpg.connect(os.environ['SECOPS_DB_DSN'])
    print(await conn.fetchval('SELECT 1'))
    await conn.close()
asyncio.run(check())
"
```

### Restart
```bash
docker restart secops-runner
```

### Update
```bash
docker pull ghcr.io/anomalyco/secops-runner:prod
docker stop secops-runner
docker rm secops-runner
# re-run the docker run command from §2
```

### Emergency stop
```bash
docker stop secops-runner
# Runs draining: the runner waits up to 30s for in-progress scans, then exits.
```

## 5. Incident Response

| Incident | Action |
|----------|--------|
| Runner crash-loop | Check `docker logs secops-runner` for PG auth errors or OOM |
| Sandbox breakout suspicion | `docker stop $(docker ps -q --filter name=strix-sandbox-)` then inspect sandbox logs |
| Tailscale disconnect | `tailscale status` — re-auth if node is gone from the mesh |
| DB unresponsive | The runner backoffs exponentially (1s, 2s, 4s, …, max 60s) — check rackboy1 PG health |

---

## 6. Migration — Colocated (rackboy1) → Dedicated (scanner-1)

### Prerequisites

- [ ] scanner-1 host provisioned per §1 (OS, Docker, Tailscale)
- [ ] Tailscale ACLs verified: `scanner-1` → `rackboy1:55432`, `scanner-1` →
      `bigboy:4000`
- [ ] Docker secrets created on scanner-1 per §2
- [ ] `deploy/scanner-1/.env.scanner-1` populated from `.example` template
- [ ] `ghcr.io/anomalyco/secops-runner:prod` exists and is recent
- [ ] rackboy1 has `SECOPS_RUN_DISPATCH_MODE=queue` in its `.env.rackboy1`
      (verifiable via `grep` on rackboy1)

### Step-by-step migration

```bash
# ── Step 1 — Boot the scanner-1 runner ─────────────────────────────────
# On scanner-1, from the repo root:
docker compose --profile scanner-pre-ga \
  --env-file deploy/scanner-1/.env.scanner-1 \
  -f deploy/scanner-1/docker-compose.scanner.yml up -d --build

# ── Step 2 — Verify scanner-1 runner is alive ───────────────────────────
# Check logs for startup and queue-polling:
docker logs secops-scanner-runner --tail 30
# Expected: "Runner started, polling run_queue..."

# Verify heartbeat healthcheck:
docker inspect --format='{{json .State.Health}}' secops-scanner-runner
# Expected: {"Status": "healthy", ...}

# ── Step 3 — Stop the rackboy1 runner (co-located) ────────────────────
# On rackboy1:
docker stop secops-prod-runner
docker rm secops-prod-runner  # prevents auto-restart on power cycle

# ── Step 4 — Verify scanner-1 claims queued runs ──────────────────────
# Any runs enqueued during the transition should be claimed within seconds:
docker logs secops-scanner-runner --tail 50
# Look for: "claimed run_id=..." and "run completed run_id=..."

# ── Step 5 — Clean up rackboy1 runner state (safe to defer) ──────────
# Remove the colocated runner image and shared volume on rackboy1:
# (Only after verifying scanner-1 is stable for ≥24h)
docker rmi secops-runner:prod
docker volume rm secops-runs-prod
```

### Validation checkpoints

| # | Check | Command | Expected |
|---|-------|---------|----------|
| V1 | scanner-1 runner container is up | `docker ps --filter name=secops-scanner-runner` | `Up`, healthy |
| V2 | scanner-1 runner health | `docker inspect --format='{{.State.Health.Status}}' secops-scanner-runner` | `healthy` |
| V3 | scanner-1 can reach PG | `docker exec secops-scanner-runner python -c "import asyncpg,asyncio,os; async def c(): conn=await asyncpg.connect(os.environ['SECOPS_DATABASE_URL']); print(await conn.fetchval('SELECT 1')); await conn.close(); asyncio.run(c())"` | `1` |
| V4 | scanner-1 can claim queue | Check logs for first `claimed run_id=` within 30s | Present |
| V5 | Finished run lands findings | Check a completed run's findings via API or PG | Findings returned |
| V6 | rackboy1 runner is stopped | `docker ps --filter name=secops-prod-runner` | Empty |
| V7 | API unaffected during migration | `curl -f https://security-ops.unicorncommander.ai/health` | `{"status":"ok"}` |

### No-downtime rationale

The migration is safe because:

1. **Queue decoupling**: `run_queue` table on rackboy1 PG is the hand-off. The API
   enqueues runs; the runner claims them. The API never blocks on runner availability.
2. **FOR UPDATE SKIP LOCKED**: `claim_next()` never blocks. If two runners race (e.g.,
   the rackboy1 runner hasn't fully stopped yet), each claims distinct queue entries.
3. **No risk of double-processing**: A claimed queue row is stamped with `claimed_at`
   + `claimed_by`. Only the claiming runner processes it. If the runner crashes, the
   run stays RUNNING and must be operator-reconciled — it never auto-requeues.
4. **PG remains on rackboy1**: Both the API and both runners connect to the SAME PG
   instance. No PG migration is involved.
5. **Rollback is the reverse**: Stop scanner-1 runner, start rackboy1 runner. The
   queue absorbs the gap with no data loss.

---

## 7. Rollback — Dedicated → Colocated

### When to rollback

- scanner-1 host becomes unreachable for >5 minutes
- scanner-1 runner cannot reach PG (rackboy1 firewall change)
- scanner-1 Docker daemon fails and cannot be restarted within 30 minutes
- Any of the "Remaining (blocked on Aaron)" readiness items are not yet satisfied
  and the runner is needed

### Step-by-step rollback

```bash
# ── Step 1 — Stop scanner-1 runner ──────────────────────────────────────
# Use the approved rollback script:
SCANNER_ROLLBACK_APPROVED=YES ./scripts/scanner-host-rollback.sh

# ── Step 2 — Start rackboy1 runner ──────────────────────────────────────
# On rackboy1:
docker compose --env-file deploy/rackboy1/.env.rackboy1 \
  -f deploy/rackboy1/docker-compose.rackboy1.yml up -d secops-runner

# ── Step 3 — Verify rackboy1 runner claims queued runs ──────────────────
docker logs secops-prod-runner --tail 30
# Expected: "claimed run_id=..." within 10s

# ── Step 4 — Re-enable docker.sock on rackboy1 (if it was removed) ─────
# This only applies if Step 5 of the migration removed it. If not, skip.
ls -la /var/run/docker.sock  # should exist
```

### Rollback validation

| # | Check | Expected |
|---|-------|----------|
| R1 | scanner-1 runner stopped | `docker ps --filter name=secops-scanner-runner` empty |
| R2 | rackboy1 runner started | `docker ps --filter name=secops-prod-runner` shows `Up` |
| R3 | rackboy1 runner claims queue | Logs show `claimed run_id=` within 10s |
| R4 | API health | `curl -f https://security-ops.unicorncommander.ai/health` returns ok |
