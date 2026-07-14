# Scanner-Host Requirements — pre-GA Prototype

**Status:** Draft — not yet approved. Based on the threat model.

## Host Requirements

| # | Requirement | Priority | Notes |
|---|-------------|----------|-------|
| R1 | Dedicated physical or VM: NO co-located sensitive workloads | **BLOCKING** | Must not share host with PHI (glitter-mane) or financial production (TPO, AO) |
| R2 | Linux kernel ≥ 6.1 (LTS) | **BLOCKING** | Docker, Tailscale compatibility |
| R3 | Docker CE 24+ | **BLOCKING** | Strix container management |
| R4 | Tailscale node (Headscale-authenticated) | **BLOCKING** | Tailnet connectivity to rackboy1 + bigboy |
| R5 | CPU ≥ 4 cores, RAM ≥ 16 GiB | **HIGH** | Parallel sandbox launch capacity |
| R6 | SSD ≥ 100 GiB (ephemeral sandbox images) | **HIGH** | Docker image cache + sandbox tmpfs |
| R7 | NO inbound firewall rules (0.0.0.0:*) | **BLOCKING** | No HTTP listener, no SSH port exposed |
| R8 | Outbound-only for internet (Docker pulls, package updates) | **HIGH** | Admin-only SSH via Tailscale SSH or jump host |
| R9 | Tailscale ACL permits scanner-1 → rackboy1:55432 (PG) | **BLOCKING** | Outbound-only DB access |
| R10 | Tailscale ACL permits scanner-1 → bigboy:4000 (LiteLLM) | **BLOCKING** | Outbound-only LLM access |
| R11 | Host OS: minimal (no GUI, no build toolchain) | **HIGH** | Reduce attack surface. Alpine Linux or Debian minimal |
| R12 | `secops-runner` runs as unprivileged user inside container | **BLOCKING** | Dockerfile USER directive |
| R13 | Strix sandbox rootfs read-only, non-root user | **BLOCKING** | Configured in `docker-compose.yml` per sandbox |
| R14 | Host OS auto-updates (unattended-upgrades) | **MEDIUM** | Kernel/docker CVEs patched within 24h |
| R15 | `SECOPS_APP_PASSWORD` never logged or printed | **BLOCKING** | Container env injection via Docker secrets or GitHub Actions variable |
| R16 | `SECOPS_INTERNAL_LITELLM_API_KEY` never logged or printed | **BLOCKING** | Same as R15 |
| R17 | run_queue polling interval ≤ 30s | **MEDIUM** | Configurable via RUNNER_POLL_INTERVAL_MS |
| R18 | No persistent state on scanner-1 | **HIGH** | Zero data at rest; sandbox ephemeral |

## Acceptance Checklist

- [ ] scanner-1 is provisioned on a dedicated host with no co-located workloads
- [ ] scanner-1 has no inbound firewall rules (only outbound)
- [ ] Tailscale is installed and authenticated to the team Headscale
- [ ] Tailscale ACLs are verified: `scanner-1` → `rackboy1:55432`, `scanner-1` → `bigboy:4000`
- [ ] Docker is installed and the runner container runs as non-root
- [ ] Strix sandbox containers are configured with read-only rootfs + non-root user
- [ ] `SECOPS_APP_PASSWORD` and `SECOPS_INTERNAL_LITELLM_API_KEY` are injected via Docker secrets
- [ ] The runner can claim a run from the queue and execute it end-to-end
- [ ] Node is logged to the security audit feed
- [ ] Unattended-upgrades are configured
