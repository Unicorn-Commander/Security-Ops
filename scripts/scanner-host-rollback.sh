#!/usr/bin/env bash
# Security-Ops — scanner-host rollback (tear down the dedicated scanner host stack).
#
# The durable migration is from rackboy1 (colocated runner) -> scanner-1
# (dedicated runner). Rolling back means killing the scanner-1 runner AND
# re-enabling the colocated runner on rackboy1. This script only handles the
# scanner-1 side. See docs/scanner-host/runbook.md §Migration for the full
# sequence.
#
# Usage:
#   SCANNER_ROLLBACK_APPROVED=YES ./scripts/scanner-host-rollback.sh
#
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# -- Guard: explicit approval -----------------------------------------------
[[ "${SCANNER_ROLLBACK_APPROVED:-}" == "YES" ]] \
  || { echo 'REFUSING: set SCANNER_ROLLBACK_APPROVED=YES to confirm rollback' >&2; exit 2; }

# -- Guard: compose file exists ---------------------------------------------
compose="$repo_root/deploy/scanner-1/docker-compose.scanner.yml"
[[ -f "$compose" ]] || { echo "REFUSING: compose file not found: $compose" >&2; exit 2; }

# -- Guard: env file exists (we will NOT create it if missing) --------------
env_file="$repo_root/deploy/scanner-1/.env.scanner-1"
[[ -f "$env_file" ]] || { echo "REFUSING: env file not found: $env_file (create from .example)" >&2; exit 2; }

# -- Step 1: show what we are about to tear down -----------------------------
echo "=== scanner-host rollback: draining and tearing down ==="
echo "  compose: $compose"
echo "  env:     $env_file"
echo ""

# -- Step 2: drain — give the runner a moment to finish its current run ------
echo "--- draining (waiting up to 30s for current run to finish) ---"
docker compose --env-file "$env_file" --profile scanner-pre-ga -f "$compose" stop --time 30 2>&1 \
  || echo "  (no running container to stop)"

# -- Step 3: remove the stack ------------------------------------------------
echo "--- removing stack ---"
docker compose --env-file "$env_file" --profile scanner-pre-ga -f "$compose" down -v 2>&1 \
  || { echo "ERROR: compose down failed" >&2; exit 3; }

# -- Step 4: post-rollback validation ----------------------------------------
echo "--- post-rollback validation ---"
if docker ps --filter name=secops-scanner-runner --format '{{.Names}}' | grep -q .; then
  echo "WARNING: scanner-runner container still running — manual cleanup needed" >&2
  exit 4
fi
echo "  scanner-runner container removed — OK"

echo ""
echo "=== Rollback complete ==="
echo ""
echo "NEXT STEPS (manual — see docs/scanner-host/runbook.md §Rollback):"
echo "  1. ssh rackboy1"
echo "  2. Ensure deploy/rackboy1/.env.rackboy1 has SECOPS_RUN_DISPATCH_MODE=queue"
echo "  3. docker compose --env-file deploy/rackboy1/.env.rackboy1 \\"
echo "       -f deploy/rackboy1/docker-compose.rackboy1.yml up -d secops-runner"
echo "  4. docker logs secops-prod-runner --tail 20  # verify it claims queue entries"
