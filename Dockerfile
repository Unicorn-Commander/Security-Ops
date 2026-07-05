# syntax=docker/dockerfile:1
# Security-Ops API — FastAPI + SQLAlchemy 2.0 (async) on Python 3.12.
# Build context is the REPOSITORY ROOT (see docker-compose.yml -> secops-api: build .).
# Runtime entrypoint per the build blueprint: uvicorn app.main:app --host 0.0.0.0 --port 8130.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# All pinned runtime deps ship cp312 manylinux wheels (asyncpg, cryptography via
# pyjwt[crypto], pydantic-core, greenlet, orjson) so no compiler is required on
# python:3.12-slim. If you later pin a dep that only ships an sdist, uncomment:
# RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
#     && rm -rf /var/lib/apt/lists/*

# --- dependency layer (cached until requirements.txt changes) ---
COPY requirements.txt ./
RUN pip install -r requirements.txt

# --- application source + migrations (canonical layout from the blueprint) ---
COPY alembic.ini ./
COPY migrations ./migrations
COPY scripts ./scripts
COPY app ./app

# Startup wrapper: apply DB migrations, then exec the CMD (uvicorn). This keeps
# the blueprint CMD exactly as specified while giving `docker compose up` a
# zero-touch "running start". `exec "$@"` makes uvicorn PID 1 for clean SIGTERM.
COPY <<'EOF' /usr/local/bin/entrypoint.sh
#!/bin/sh
set -e
echo "[secops-api] applying database migrations (alembic upgrade head)..."
alembic upgrade head
echo "[secops-api] starting: $*"
exec "$@"
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8130

# Liveness = the app's root /health route (defined directly in app.main, no auth,
# always present even before the /api router is wired — unlike /api/v1/health).
HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=5 \
  CMD python -c "import urllib.request as u,sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8130/health',timeout=4).status==200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8130"]
