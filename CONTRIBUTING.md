# Contributing to Security-Ops

Security-Ops is for authorized testing. Changes that start a scan must keep going through `app.authz.gate.enforce_scope`. A new engine, a queue worker, or an MCP tool does not get its own exception.

## Setup

Follow [README.md](README.md): copy `.env.example` to `.env`, start Postgres, and apply migrations. For a local API without Keycloak, set `SECOPS_ENVIRONMENT=development` and `SECOPS_AUTH_BYPASS=true`. The bypass is ignored outside development.

## Checks

```bash
pip install -r requirements.txt -r requirements-dev.txt
make test
```

`make test` runs `python -m pytest` against the SQLite unit suite. Row-level security tests in `tests/test_rls_postgres.py` run only when `SECOPS_TEST_DATABASE_URL` points at Postgres as a role that is not a superuser and does not have `BYPASSRLS`.

The frontend has no lint script. Build it with:

```bash
cd frontend && npm install && npm run build
```

## Pull requests

- Describe the operator-visible change and how you tested it.
- Keep tenant filters on `org_id`. A cross-organization id should 404.
- Do not log tokens, cloud credentials, or raw secrets from a scanner report.
- Do not commit `.env` or a real personal access token. The plaintext of a token is shown once and stored as a hash.
- This repository is licensed under the Apache License 2.0. Contributions are made under the same licence. See [LICENSE](LICENSE).

By opening a pull request you confirm you wrote the change or have the right to submit it under that licence.
