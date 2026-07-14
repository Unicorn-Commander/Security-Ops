# Scanner-Host Production Readiness Checklist

**Status:** Pre-GA — every item below is a gate to marking the dedicated
scanner host as "production ready." Items marked **Aaron** require Aaron's
approval, provisioned infrastructure, or secret material.

---

## ⚠️ BLOCKING — must be done before any production run

| # | Item | Owner | Artifact / Evidence |
|---|------|-------|---------------------|
| B1 | **Provision scanner-1 host** — dedicated physical/VM running Debian 12 minimal, no co-located workloads (no PHI, no financial production) | **Aaron** | `ssh scanner-1` → `hostname` |
| B2 | **Install Docker CE 24+** on scanner-1 | **Aaron** | `docker --version` |
| B3 | **Install Tailscale** on scanner-1, auth to team Headscale | **Aaron** | `tailscale status` shows node |
| B4 | **Configure Tailscale ACLs** — permit `scanner-1` → `rackboy1:55432` (PG) and `scanner-1` → `bigboy:4000` (LiteLLM) | **Aaron** | `tailscale ping rackboy1`, `tailscale ping bigboy` |
| B5 | **Create `deploy/scanner-1/.env.scanner-1`** from `.env.scanner-1.example` — populate `SECOPS_DB_HOST=rackboy1`, port `55432`, `SECOPS_LITELLM_BASE_URL=https://bigboy:4000` | **Aaron** | File exists `chmod 600` |
| B6 | **Create Docker secrets** on scanner-1: `SECOPS_APP_PASSWORD` (the `secops_app` PG role password) and `SECOPS_INTERNAL_LITELLM_API_KEY` | **Aaron** | `docker secret ls` shows both, verify via `docker exec` |
| B7 | **Deploy scanner-1 runner** via `docker compose --profile scanner-pre-ga -f deploy/scanner-1/docker-compose.scanner.yml up -d` | **Aaron** | `docker ps` shows `secops-scanner-runner` `Up` + healthy |
| B8 | **Verify scanner-1 runner can connect to PG** on rackboy1 over tailnet | **Aaron** | V3 validation checkpoint in runbook §6 |
| B9 | **Verify scanner-1 runner can claim and execute a run** — create a PENDING run via API, verify scanner-1 claims and completes it | **Aaron** | Logs show `claimed run_id=…` + `run completed run_id=…` |
| B10 | **Verify authorization gate is preserved** — confirm the runner still gate-checks before claiming (gate is server-side in `start_run`, but verify the full path) | **Aaron** | Run against an out-of-scope target returns 403 |
| B11 | **Socket exposure review** — verify scanner-1 has NO inbound ports (`0.0.0.0:*`). Only Tailscale SSH, outbound Docker daemon, and tailnet connectivity. | **Aaron** | `ss -tlnp` shows nothing listening on `0.0.0.0` |
| B12 | **Run-drift test for migration** — run a scan BEFORE and AFTER migration; compare findings to prove no processing regressions | **Aaron** | Two findings sets match |
| B13 | **Approve production topology migration** — confirm Aaron's explicit OK on the switch from co-located runner on rackboy1 to dedicated runner on scanner-1 | **Aaron** | Signed-off in Project-Ops task |

---

## 🔴 HIGH — should be done before going live

| # | Item | Owner | Artifact / Evidence |
|---|------|-------|---------------------|
| H1 | **Stop rackboy1 `secops-prod-runner`** after scanner-1 is verified — remove the colocated runner container to eliminate double-claim risk | **Aaron** | `docker ps` on rackboy1 shows no `secops-prod-runner` |
| H2 | **Verify concurrent-run safety** — load-test with parallel run enqueues, confirm each `claim_next` returns distinct rows | Developer | Covered by test A6 (`test_a6_no_double_claim`) |
| H3 | **Configure `unattended-upgrades`** on scanner-1 for kernel/Docker CVEs | **Aaron** | `dpkg -l unattended-upgrades` |
| H4 | **Set `SECOPS_APP_LOG_LEVEL=warning`** on scanner-1 to reduce log volume in production | **Aaron** | Verify in `.env.scanner-1` |
| H5 | **Verify PG connection uses TLS** — confirm `asyncpg` connects with `ssl=require` equivalent. Currently unclear whether rackboy1 PG enforces TLS for tailnet connections; verify and document | Developer | TBD |

---

## 🟡 MEDIUM — should be done in the first week post-migration

| # | Item | Owner | Artifact / Evidence |
|---|-------|-------|---------------------|
| M1 | **Remove `secops-runner:prod` image and `secops-runs-prod` volume** from rackboy1 (after 24h stability confirmation) | **Aaron** | `docker rmi` + `docker volume rm` |
| M2 | **Add container CPU/memory limits** to scanner-1 compose (`deploy:` block) — prevent runaway sandbox from starving the host | Developer | Updated `docker-compose.scanner.yml` |
| M3 | **Add structured JSON logging** on the runner if not already default (config.py uses JSON log format in production) | Developer | Log lines parse as JSON |
| M4 | **Set up host-level monitoring** (Prometheus node_exporter + cockpit or similar) for scanner-1 | **Aaron** | `curl localhost:9100/metrics` |
| M5 | **Drain-and-remove edge route** if rackboy1's `docker.sock` was ever internet-reachable via a Traefik path (it should not have been, but verify) | Developer | No Traefik route references runner |
| M6 | **Dry-run rollback** from the runbook (in staging or against bigboy dogfood) to verify `SCANNER_ROLLBACK_APPROVED=YES` path | Developer | Rollback test passes |

---

## ✅ Already delivered (code + docs side)

| # | Item | Status |
|---|------|--------|
| D1 | `deploy/scanner-1/docker-compose.scanner.yml` | Done — profile-gated (`scanner-pre-ga`), no inbound ports, heartbeat healthcheck, file-based secrets |
| D2 | `deploy/scanner-1/.env.scanner-1.example` | Done — all runner env vars with safe defaults |
| D3 | `Dockerfile.runner` | Done — separate runner image (never API) with minimal python:3.12-slim |
| D4 | `docs/scanner-host/threat-model.md` | Done — 6 threats documented with mitigations |
| D5 | `docs/scanner-host/requirements.md` | Done — 18 requirements (R1-R18) |
| D6 | `docs/scanner-host/runbook.md` | Done — provisioning, deploy, secrets, day-2 ops, IR, migration, rollback |
| D7 | `scripts/scanner-host-rollback.sh` | Done — guard-gated rollback with drain + validation |
| D8 | `tests/test_acceptance_scanner.py` (A1-A9) | Done — 8 tests covering queue lifecycle, RLS, no-double-claim, end-to-end |
| D9 | `tests/test_scanner_host_artifacts.py` | Done — 3 tests for opt-in profile, file-based secrets, rollback guard |
| D10 | Queue dispatch logic (`app/repositories/run_queue.py`, `app/runner/loop.py`, `app/services/runs.py`) | Done — mature, tested, deployed on bigboy + rackboy1 |