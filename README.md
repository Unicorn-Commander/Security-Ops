# Security-Ops

**Autonomous, authorized penetration-testing for the Unicorn Commander `*-Ops` suite.**

Security-Ops embeds the open-source [Strix](https://github.com/usestrix/strix) offensive
engine and wraps it in the trust + productization layer Strix deliberately omits: a
first-class **authorization gate** (proof you are allowed to test a target), engagement
management, an immutable audit log, suite SSO + entitlements, and a hand-off to Brigade
agents for triage & remediation. Security-Ops *finds*; Brigade *fixes*.

> **Source of truth:** the build spec at
> `/Users/aaronstransky/Documents/security-ops-build-spec.md`
> (bake-off results + decisions in memory `project_security_ops_strix.md`).
> Read §1–§4 before changing any core behavior — the decisions there are settled.

---

## Status — Phase 1 (skeleton + the gate)

This deployment stands up the app scaffold, SSO + entitlement wiring, and the
**authorization gate + engagement / target / audit model**. The gate is enforced
server-side; **no scan runs without an active, attested, unexpired scope.** The Strix
runner, findings pipeline, reporting, and Brigade hand-off land in Phase 2 — those
endpoints (`.../report`, `.../handoff`) return `501` for now.

**Running-start proof.** After the stack is up and migrated, seed the pilot:

```bash
make seed            # docker compose exec secops-api python -m scripts.seed_pilot
```

This creates the pilot org, registers + attests the self-owned target
`brigade.unicorncommander.ai` (method `OWNED`, checkbox + typed confirmation), and
activates an engagement scoped to it. Afterward
`enforce_scope(engagement, "https://brigade.unicorncommander.ai/…")` returns cleanly
while any out-of-scope target raises `AuthorizationDenied` (HTTP 403) — the gate
demonstrated end-to-end, with one append-only audit row per decision.

---

## Isolation posture (non-negotiable — spec §3)

Security-Ops runs in **its own container, its own Postgres, its own network, its own
credentials, its own audit log.** It never shares a process / DB / network with Brigade
or with customer data. This isolation *is* the enterprise-sales posture.

| Service          | Container         | Host port | In-container | Notes                                       |
|------------------|-------------------|-----------|--------------|---------------------------------------------|
| API (FastAPI)    | `secops-api`      | `8130`    | `8130`       | `uvicorn app.main:app`                      |
| Postgres 16      | `secops-db`       | `5436`    | `5432`       | named volume `secops-pgdata`                |
| Frontend (nginx) | `secops-frontend` | `8131`    | `8131`       | SPA + `/api` proxy → `secops-api:8130`      |

All three share the single private network `secops-net`.

---

## Quick start (Docker Compose)

```bash
cp .env.example .env         # then edit: Keycloak issuer, DB creds, (Phase 2) litellm key
make build                   # docker compose build
make up                      # docker compose up -d
```

On boot the API entrypoint waits for `secops-db` to become healthy, then runs
`alembic upgrade head` automatically before starting uvicorn — so `up` is a zero-touch
running start. Then:

- API health: <http://localhost:8130/api/v1/health>
- Frontend:   <http://localhost:8131>
- Postgres:   `localhost:5436`

Prove the gate, then tear down:

```bash
make seed
make down                    # docker compose down   (add `-v` to also drop the DB volume)
```

---

## Local dev (no containers)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

docker compose up -d secops-db        # just the database
export SECOPS_DATABASE_URL=postgresql+asyncpg://secops:secops@localhost:5436/secops
make migrate                          # alembic upgrade head
make dev                              # scripts/dev.sh -> uvicorn --reload on :8130
```

Frontend dev server (Vite; proxies `/api` → `:8130`):

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173
```

**Dev auth:** set `SECOPS_ENVIRONMENT=development` and `SECOPS_AUTH_BYPASS=true` to skip
Keycloak locally — the bypass is honored *only* in development.

---

## Configuration

All backend settings load through `app/core/config.py` (`pydantic-settings`, `SECOPS_`
prefix, `.env`-backed, cached `settings` singleton — never read `os.environ` elsewhere).
Every key is documented in **`.env.example`**; the load-bearing ones:

- `SECOPS_DATABASE_URL` — async SQLAlchemy URL (also accepts bare `DATABASE_URL`).
- `SECOPS_KEYCLOAK_ISSUER` / `SECOPS_KEYCLOAK_REALM` (`uchub`) / `SECOPS_KEYCLOAK_CLIENT_ID`.
- `SECOPS_ENTITLEMENT_SKU` (`security-ops`) — realm role `app-security-ops` grants access.
- `SECOPS_INTERNAL_LITELLM_BASE_URL` — **internal-direct** litellm, *not* the
  Cloudflare-fronted public gateway (long autonomous runs 504 through CF; spec §7).
- `SECOPS_STRIX_SANDBOX_IMAGE`, `SECOPS_RUNS_DIR` — Phase 2 engine.
- `SECOPS_EMERGENCY_STOP_ALL` — global kill-switch honored by the gate.

`docker-compose.yml` injects the API's `SECOPS_DATABASE_URL` for the in-network DB host
(`secops-db:5432`), overriding the `.env` value (which targets `localhost:5436` for
host / venv runs).

---

## The authorization gate (the product IP — spec §4)

Two distinct authorizations, kept separate in code:

1. **Operator authz** — Keycloak SSO (realm `uchub`) + the `security-ops` entitlement SKU.
   Every business route depends on an entitled user (`EntitledUser`).
2. **Target authz — THE GATE** (`app.authz.gate.enforce_scope`) — a scan may touch a
   target only if it falls inside an **active, unexpired** engagement's scope, is not
   excluded, and is covered by a **valid attested** `AuthorizedTarget`. It is invoked
   server-side in `services.runs.start_run`; the engine is **never** trusted to
   self-limit. Every decision is appended to a **hash-chained, append-only** audit log
   (SOC2 evidence).

---

## Migrations

Alembic (async). `alembic.ini` sets `script_location = migrations`; the URL is overridden
at runtime from `settings.database_url` by `migrations/env.py`. The API container
auto-applies migrations on start — run manually with `make migrate`
(`alembic upgrade head`).

- `0001_initial` — the org / target / engagement / run / finding / audit schema.
- `0002_org_rls` — org-level row-level security (below). PostgreSQL-only; a clean
  no-op on the sqlite unit-test DB.

---

## Row-level security — multi-tenant isolation (spec §5)

A pentest product must never leak findings across tenants, so isolation is enforced
in **two independent layers**:

1. **App layer** — every business route resolves `CurrentOrg` and the repositories
   compare/filter `org_id`; a cross-org id renders as 404.
2. **Database layer** (`0002_org_rls` + `app/db/rls.py`) — Postgres RLS policies on
   `authorized_targets`, `engagements`, `runs`, `findings`, `audit_events`, keyed on
   the session GUC `app.current_org_id`. `get_current_org` binds that GUC once per
   request (`set_org_context`); the detached Strix worker binds it from the run's
   `org_id`; `get_session` clears it on teardown so a pooled connection never leaks
   context. Because a `Session` releases its connection on every `commit()` (and
   services commit mid-request), each request/worker is **pinned to one checked-out
   connection** so the GUC applies to every statement across those commits —
   otherwise a later query could hop to a GUC-less pooled connection and RLS would
   silently return zero rows. **Fail-closed:** with no GUC the predicate
   `org_id = NULL` is never true, so zero rows are visible or writable.
   `organizations` is intentionally unpoliced (the slug lookup bootstraps the GUC);
   `audit_events` allows NULL-`org_id` system rows to be appended but still
   restricts *reads* to the caller's org.

   Verified live against Postgres 16 as a non-superuser owner role: per-table
   isolation both directions, `WITH CHECK` rejecting a cross-org insert, fail-closed
   zero-rows with no context, the GUC surviving mid-request commits, and pinning
   holding under a multi-connection pool with concurrent tenants.

> **⚠️ GA activation step — the runtime DB role must NOT be a superuser or hold
> `BYPASSRLS`.** RLS (even `FORCE`d) is bypassed by superusers, and the stock
> `postgres` image makes `POSTGRES_USER` (`secops`) a superuser — so the policies
> ship **safely and non-breakingly** but do not yet *enforce* until the app connects
> as a dedicated non-superuser role. Before multi-tenant GA, create one and point
> `SECOPS_DATABASE_URL` at it, e.g.:
>
> ```sql
> CREATE ROLE secops_app LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;
> GRANT secops TO secops_app;            -- inherit table ownership/grants
> ```
>
> The RLS isolation itself is proven by `tests/test_rls_postgres.py` (skips without
> a `SECOPS_TEST_DATABASE_URL` Postgres, which must use a non-`BYPASSRLS` role); the
> full app-path validation against a live non-superuser Postgres is the remaining
> GA gate.

---

## Make targets

`make dev` · `make migrate` · `make seed` · `make test` · `make build` · `make up` · `make down`

---

## Deploy targets (spec §9)

Dogfood **`security-ops.magicunicorn.dev`** first (E2E-verify the gate + the self-owned
engagement), then prod **`security-ops.unicorncommander.ai`** behind SSO +
email-allowlist early-access + the entitlement SKU. Ops-Center tiles both sites. Keep
rollback tags.

---

## Guardrails (non-negotiable — spec §11)

- **No scan without an active, attested, unexpired scope.** The server enforces it; never the engine.
- Offensive capability stays behind its own entitlement + audit; trivially disable-able per customer.
- Isolation (own container / DB / network / creds) is not optional.
- Only ever test assets the operator owns or is attested-authorized to test.
