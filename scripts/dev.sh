#!/usr/bin/env bash
# Security-Ops — local dev runner (README "Local dev"): uvicorn --reload on :8130.
#
# Assumes deps are installed (`pip install -r requirements.txt`) and the database
# is reachable via SECOPS_DATABASE_URL / DATABASE_URL. Apply migrations first with
# `make migrate`. Override host/port with SECOPS_HOST / SECOPS_PORT.
set -euo pipefail

# Run from the repo root so the `app` package is importable.
cd "$(dirname "$0")/.."

# Default to development so the dev auth-bypass (SECOPS_AUTH_BYPASS) can be honored.
export SECOPS_ENVIRONMENT="${SECOPS_ENVIRONMENT:-development}"

HOST="${SECOPS_HOST:-0.0.0.0}"
PORT="${SECOPS_PORT:-8130}"

echo "[dev] uvicorn app.main:app --reload  (${HOST}:${PORT}, environment=${SECOPS_ENVIRONMENT})"
exec uvicorn app.main:app --reload --host "${HOST}" --port "${PORT}"
