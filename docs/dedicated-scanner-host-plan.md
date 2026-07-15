# Security-Ops — Dedicated Scanner Host (plan)

**PO:** P-00099 task `5dadd56f` (NEXT, pre-GA) · **Status:** plan + decision gate
**Prepared:** 2026-07 (Claude)

## Problem
The offensive **runner** (`Dockerfile.runner`, 8 engines: nuclei · gitleaks · trivy ·
opengrep · OWASP ZAP · naabu · Prowler · attack-path) runs **host-root** — `docker.sock`
+ host networking — **co-located on rackboy1** next to PHI (Glitter Mane) and finance
(Wealth-Ops, Accounting-Ops) apps. An offensive toolchain with host-root, one bad
CVE/misconfig away from the same host as regulated data, is the top pre-GA risk. It must
move to a **dedicated, network-isolated host** where a runner compromise cannot reach the
sensitive neighbors.

## Target architecture (control-plane / worker split)
- **Control plane stays on rackboy1**: `secops-api` (engagements, targets, attestation
  gate, findings). It **enqueues** jobs instead of exec-ing engines locally.
- **Scanner host = a dedicated worker**: a `runner-agent` authenticates to `secops-api`,
  **pulls** queued+gate-cleared jobs, runs the engines locally (host-root contained to
  THIS box), and **posts findings back**. No inbound to the scanner host; no remote
  `docker.sock` exposure.
- **The scan gate stays authoritative**: a job is only enqueued after the existing
  active-engagement + in-scope-target + valid-attestation checks pass. The worker trusts
  only signed/enqueued jobs — it never scans on its own.

Prefer the **pull model** over `DOCKER_HOST`-over-TLS: exposing a remote docker socket is
as dangerous as the co-location we're fixing.

## Network isolation (the whole point)
Headscale ACL for the scanner host:
- **Allow:** → `secops-api` (job channel only) · → the internet / authorized scan targets.
- **Deny:** → the PHI/finance app segment (Glitter Mane, Wealth-Ops, AO, Postgres/Redis/
  Qdrant, other tailnet apps). The scanner must have **no route** to sensitive neighbors.
- Egress for external pentests should leave from an IP that won't trip the fleet's own
  defenses.

## Host options (this is the decision gate for Aaron)
| Option | Isolation | Cost | Best for |
|---|---|---|---|
| **Dedicated VPS** (majiks-vps pattern) | Strong — off-fleet, clean egress | low monthly | external-target pentests; recommended default |
| **Spare fleet node** (a lilguy / spare rackboy) in an isolated segment | Strong if ACL'd off the sensitive net | sunk hardware | internal-only scanning |
| **Ephemeral cloud runner per engagement** | Strongest (fresh + destroyed) | spin-up latency + per-run cost | high-assurance / client engagements |

**Recommendation:** a **dedicated VPS** for external scanning (clean isolated egress), or a
**spare node** if the near-term target mix is internal-only. Ephemeral-per-engagement is the
GA-grade end state. **Blocker = which host + budget — your call.**

## Migration steps (once the host is chosen)
1. Provision host; install the runner image + engine toolchain (`Dockerfile.runner`).
2. Stand up `runner-agent` (config: `secops-api` URL + a scoped worker token).
3. Apply the Headscale ACL isolating it from the PHI/finance segment; verify it **cannot**
   reach a sensitive neighbor (negative test).
4. Change `secops-api` job dispatch from local-exec → enqueue; worker pulls.
5. Cut over; run a real gate-checked scan end-to-end from the isolated host; confirm
   findings post back.
6. **Decommission the co-located runner on rackboy1.**

## Interim hardening (do now, until the move)
Partial risk reduction while the host decision is pending: run the rackboy1 runner with a
restricted seccomp/AppArmor profile, drop unneeded capabilities, front `docker.sock` with a
socket-proxy (allow only the calls the runner needs), and add a network policy limiting the
runner container's reach to its sensitive neighbors. This shrinks — but does not close — the
co-location risk; the dedicated host is still required for GA.
