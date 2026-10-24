# Security policy

## Authorized use

Security-Ops scans only targets covered by an active engagement and a current attestation. Use it on systems you own or have permission to test. Finding a vulnerability in someone else's system is not a report to this project.

## Reporting a vulnerability in this project

Report vulnerabilities in Security-Ops itself through GitHub private vulnerability reporting:

<https://github.com/Unicorn-Commander/Security-Ops/security/advisories/new>

Please include the version (`GET /version` or the tag you built), the affected area (API, console, MCP, runner, migrations), and the impact. Do not include live credentials, customer data, or a proof that would scan a third party.

There is no security contact address checked into this repository. A public GitHub issue is the wrong place for an unfixed vulnerability.

## What the server already enforces

- A run is created only after `app.authz.gate.enforce_scope` allows every target.
- MCP tools use that same service layer. Personal access tokens cannot use the admin-only attestation methods.
- `SECOPS_AUTH_BYPASS` is honored only when `SECOPS_ENVIRONMENT=development`.
- `SECOPS_EMERGENCY_STOP_ALL` denies new scans.
- Agent tokens are stored as a SHA-256 hash, returned once, and time-limited when minted.

If you believe one of those controls can be skipped, that is the report we want.
