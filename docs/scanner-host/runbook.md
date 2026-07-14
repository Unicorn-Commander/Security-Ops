# Scanner-Host Runbook — secops-runner Deployment

**Status:** Pre-GA prototype. Do NOT deploy to production without Aaron approval.

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
