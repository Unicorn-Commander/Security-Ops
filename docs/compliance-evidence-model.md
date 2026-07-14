# Security-Ops compliance and rollout evidence model

This document captures the implementation slice for the GPT-5.4-mini queue:

- SIEM + audit-trail hash-chain integration
- continuous-control monitoring / posture-over-time
- external-customer GA architecture and rollout planning
- SOC 2 / HIPAA evidence mapping
- per-user org/workspace tenancy

## Current implementation slice

- `GET /api/v1/compliance` returns a tenant-scoped posture snapshot.
- `GET /api/v1/compliance/audit-events` exports the immutable audit trail in a SIEM-friendly shape.
- Tenant resolution accepts either the stable org slug or the Keycloak workspace/group claim.
- The audit trail remains append-only and hash-chained (`prev_hash -> event_hash`).

## Evidence sources

- AuthZ gate decisions: `SCOPE_CHECK_ALLOWED`, `SCOPE_CHECK_DENIED`
- Target lifecycle: `TARGET_REGISTERED`, `TARGET_ATTESTED`, `TARGET_REVOKED`
- Run lifecycle: `RUN_STARTED`, `RUN_STOPPED`, `RUN_COMPLETED`
- Finding lifecycle: `FINDING_RECORDED`, `FINDING_TRIAGED`
- Tenant isolation: `CurrentOrg`, Postgres RLS, org-scoped repository predicates

## Framework mapping

The API exposes a lightweight mapping for the current slice:

- SOC 2 CC7.2 and CC8.1 map to gate enforcement plus the hash-chained audit log.
- HIPAA 164.312(b) and 164.312(c)(1) map to the org-scoped audit feed and integrity chain.

This is an evidence model, not a legal certification statement.

## External-customer GA plan

- Keep the customer-facing launch behind Aaron approval.
- Keep billing, entitlement tiers, and dedicated infrastructure as configuration-gated rollout steps.
- Do not widen scan authorization or tenant scope as part of GA.
- Require adversarial tenant-isolation tests before any production customer launch.

## Rollout posture

- Dogfood first.
- Verify the `/api/v1/compliance` and `/api/v1/compliance/audit-events` surfaces on the live stack.
- Confirm no scan gate regression, no cross-tenant leakage, and no change to SSO behavior.
