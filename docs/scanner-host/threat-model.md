# Scanner Host Threat Model — Dedicated Offensive Runner

**Status:** Pre-GA design/prototype — NOT deployed. This document is the
security review of the planned dedicated scanner host migration. The current
runner (rackboy1 colocated) is documented separately in
`deploy/rackboy1/README.md`.

**Document owner:** Security-Ops (Sarge) engineering
**Date:** 2026-07-14
**Version:** v0.1-prototype

---

## 1. Scope

This threat model covers the **planned dedicated scanner host** (codename
`scanner-1`) that will host the `secops-runner` sidecar in isolation from
sensitive workloads. The scanner host's sole purpose is to execute
gate-cleared penetration-test runs.

### In scope
- Physical/virtual host provisioned exclusively for the runner
- Docker daemon and `secops-runner` container
- Strix sandbox containers launched by the runner
- Network path from scanner-host → rackboy1 Postgres (tailnet)
- Network path from scanner-host → internal LiteLLM gateway (tailnet)
- Secrets: `SECOPS_APP_PASSWORD`, `SECOPS_INTERNAL_LITELLM_API_KEY`
- Image build pipeline for `secops-runner:prod`

### Out of scope (existing controls)
- The API layer on rackboy1 (rackboy1 API is unchanged)
- The authorization gate (scope/attestation enforcement — existing, audited)
- The frontend/console UI
- Keycloak SSO
- External-customer billing/entitlement (GA scope)

---

## 2. Architecture (Target)

```
┌─────────────────────────────────────────────┐
│                scanner-1                     │
│  ┌────────────────────────────────────┐     │
│  │ secops-runner container            │     │
│  │  (network_mode: host; docker.sock) │     │
│  │  │                                  │     │
│  │  ├─ claims run_queue ─tailnet──→ rackboy1:55432 (PG) │
│  │  ├─ launches Strix sandbox containers              │
│  │  └─ routes LLM calls ─tailnet──→ bigboy:4000       │
│  └────────────────────────────────────┘     │
│                                              │
│  ┌────────────────────────────────────┐     │
│  │ Strix sandbox containers          │     │
│  │  (bridge network per sandbox)      │     │
│  │  └─ reach targets via docker NAT   │     │
│  └────────────────────────────────────┘     │
│                                              │
│  Docker socket (/var/run/docker.sock)        │
│    mounted ONLY into secops-runner          │
└─────────────────────────────────────────────┘

rackboy1 (unchanged):
  └── secops-api (no docker.sock, no host net)
  └── secops-db (Postgres, bound 127.0.0.1:55432)
  └── secops-oauth2-proxy
  └── secops-frontend
```

---

## 3. Threats

### T1 — Runner container compromise → host root
| Field | Value |
|-------|-------|
| **Threat** | An attacker exploiting a vulnerability in the runner process or a Strix engine gains code execution inside the `secops-runner` container. The container has `network_mode: host` and mounts `docker.sock` (host root on scanner-1). |
| **Impact** | Complete host compromise of scanner-1. The runner host contains NO PHI, NO financial data, NO customer secrets — only the ability to launch more sandbox containers and reach the DB. |
| **Likelihood** | Medium — Strix and Nuclei handle untrusted network responses |
| **Mitigations** | 1. scanner-1 carries NO sensitive data (no PHI, no billing, no secrets beyond the app password and LLM key) 2. The runner uses `python:3.12-slim` with minimal packages 3. Strix sandboxes are ephemeral 4. The authorization gate is SERVER-SIDE: even a fully compromised runner cannot scan an unauthorized target (it would be refused at the gate) |
| **Residual risk** | Attacker on scanner-1 can disrupt scans, read findings in transit over the tailnet to the DB, and use the host as a pivot. |

### T2 — Database credential theft
| Field | Value |
|-------|-------|
| **Threat** | `SECOPS_APP_PASSWORD` (the `secops_app` PG role password) is exfiltrated from scanner-1. `secops_app` is NOSUPERUSER NOBYPASSRLS — RLS enforces tenant isolation. |
| **Impact** | Attacker can read/write run and finding data for the authorized tenant, but cannot bypass RLS to reach other tenants. Cannot create superuser roles, cannot read other orgs' data. |
| **Likelihood** | Low — the password is container-env-only and never logged |
| **Mitigations** | 1. `secops_app` is NOSUPERUSER NOBYPASSRLS 2. RLS enforced on every tenant table 3. Password rotated per deploy |
| **Residual risk** | Data exfiltration of the tenant's runs and findings. |

### T3 — LLM API key theft → billing abuse
| Field | Value |
|-------|-------|
| **Threat** | `SECOPS_INTERNAL_LITELLM_API_KEY` is exfiltrated. |
| **Impact** | Attacker can call the internal LiteLLM gateway incurring cost, but only from the tailnet (the key is validated against the gateway's IP allowlist + the tailnet). |
| **Likelihood** | Low |
| **Mitigations** | 1. Key is container-env-only 2. LiteLLM gateway is tailnet-only (not internet-reachable) 3. Gateway has rate limits and spend caps 4. Key is scoped to `strix-*` models only |
| **Residual risk** | Abuse of internal LLM quota |

### T4 — Strix sandbox breakout
| Field | Value |
|-------|-------|
| **Threat** | A compromised Strix sandbox container breaks out to the scanner-1 host via a Docker/kernel exploit. |
| **Impact** | Same as T1 — host root on scanner-1 (which is already the runner's host). The sandbox has no additional privilege. |
| **Likelihood** | Low (Docker is run with default seccomp, AppArmor if available) |
| **Mitigations** | 1. Sandbox runs as a non-root user inside the container 2. Read-only root filesystem 3. No host mounts into the sandbox 4. No capabilities beyond `NET_ADMIN` (network manipulation for testing) 5. Ephemeral — destroyed after each run |
| **Residual risk** | A kernel 0-day could break out; mitigated by keeping the host kernel patched. |

### T5 — Tailnet traffic interception
| Field | Value |
|-------|-------|
| **Threat** | Another tailnet node intercepts the runner's connections to rackboy1's Postgres or bigboy's LiteLLM gateway. |
| **Impact** | Findings in transit could be read; database queries could be observed. |
| **Likelihood** | Low — Tailscale traffic is encrypted with WireGuard (end-to-end) |
| **Mitigations** | 1. Tailscale (WireGuard) encrypts all tailnet traffic 2. Postgres connection is TLS (asyncpg uses `ssl=require` when the PG server has TLS) 3. LiteLLM is called over HTTPS internal |
| **Residual risk** | A node with Tailscale key can route traffic; mitigated by Headscale ACLs (only scanner-1 → rackboy1:55432 and scanner-1 → bigboy:4000 allowed). |

### T6 — Denial of service via run_queue flooding
| Field | Value |
|-------|-------|
| **Threat** | An attacker with a valid PAT enqueues hundreds of runs, overloading scanner-1. |
| **Impact** | Legitimate runs are delayed; scanner-1 resource exhaustion. |
| **Likelihood** | Medium (PAT can be created by any org member) |
| **Mitigations** | 1. `max_runs` per engagement 2. Budget caps per campaign (prototype) 3. Runner claims one queue entry at a time 4. Rate limiting on the API is backlogged |
| **Residual risk** | A tenant could still flood their OWN queue; that is a tenant-self-DoS, not cross-tenant. |

---

## 4. Isolation Boundary

```
scanner-1 isolation properties:
├── No PHI, PII, financial data, or customer secrets ON THE HOST
├── No internet-facing ports (no 0.0.0.0:*, no Traefik, no edge)
├── Tailscale only: connects to rackboy1 (PG) + bigboy (LiteLLM)
├── No inbound network service (runner binds nothing — outbound-only)
├── Docker socket is the ONLY Unix-domain surface
├── Host OS: minimal Linux (no GUI, no SSH-by-password, Tailscale SSH or mTLS)
└── Ephemeral Strix sandboxes with read-only rootfs
```

Compared to the current rackboy1 colocation, the dedicated host:
- Eliminates the shared blast radius with PHI (glitter-mane) and financial
  production (TPO/AO)
- Keeps the same queue-based dispatch (config change, not rewrite)
- Adds one more host to manage (trade space for safety)

---

## 5. Data Flow

1. **API (rackboy1)**: creates a `PENDING` run + `run_queue` row after gate clearance
2. **Scanner-1 (runner)**: polls `run_queue` via tailnet → rackboy1:55432 (PG)
3. **Scanner-1 (runner)**: claims the oldest unclaimed row (`FOR UPDATE SKIP LOCKED`)
4. **Scanner-1 (runner)**: commits the claim, then executes the run:
   a. Spawns Strix sandbox (Docker container via local socket)
   b. Strix sends LLM calls → bigboy:4000 (LiteLLM, tailnet)
   c. Findings are written back to PG (rackboy1) via the runner's DB session (RLS-bound)
5. **Scanner-1 (runner)**: deletes the queue row, loops

No data at rest on scanner-1 beyond the ephemeral sandbox filesystems
(destroyed on container removal).
