# Security-Ops scan engines

Security-Ops is a **scanner-orchestration platform**, not a single scanner. Eight
engines ride one gate-cleared execution pipeline; each is a thin subclass of
`StrixRunner` that overrides only three seams. This doc is the per-engine reference for
wiring the next one.

## The shared spine

`app/engine/strix_runner.py` defines the base `StrixRunner` class. Its `execute()`
method (`strix_runner.py:724`) is the **engine-agnostic** pipeline every engine reuses:

```
emergency-stop re-check (§11)  →  PENDING→RUNNING (+ commit)  →  spawn subprocess + wait
  →  parse outputs  →  store findings (dedup + audit + SSE trace)  →  hybrid verify pass
  →  terminal status COMPLETED / FAILED / STOPPED (+ audit + commit)
```

An engine differs from the base only in **three override seams** (documented at
`strix_runner.py:952-983`):

| Seam | Method | Responsibility |
|------|--------|----------------|
| Build the command | `prepare()` | make the run dir, write the advisory scope note, build `StrixInvocation` (argv + env + log/pid paths) |
| Read the results | `_build_result()` | parse this engine's on-disk output into a `StrixRunResult` (list of `ParsedVulnerability` + metadata) |
| Report success | `_engine_completed()` | decide "did the scan finish cleanly?" independent of the raw exit code |

`_build_result()` may be sync or async — `_spawn_and_wait()` awaits it if it returns an
awaitable (`strix_runner.py:948`); Trivy uses this to run async CVE enrichment.

**Dispatch:** `_runner_for_engine(engine, session)` (`strix_runner.py:1307`) maps the
run's `engine` string to the right subclass (`nuclei` / `gitleaks` / `trivy` / `prowler`
/ `opengrep` / `zap` / `naabu`), falling back to `StrixRunner` for anything else
(default `strix`). The background entrypoint `execute_run()` loads the run + engagement
in an RLS-bound session and calls it.

**Allowlist:** `RunCreate._known_engine` (`app/schemas/run.py:49-57`) rejects any
`engine` not in
`{strix, nuclei, gitleaks, trivy, prowler, opengrep, zap, naabu}` at the API boundary.

### Every engine rides the same guarantees

By the time `prepare()` runs, `services.runs.start_run` has already cleared **every
target** through `app.authz.gate.enforce_scope`: the engagement is ACTIVE + unexpired,
the target is in-scope + not excluded, and it carries a currently-valid **attestation**.
The runner never re-opens the gate — it only re-checks the **emergency stop** before
spawning (`strix_runner.py:740`). All eight engines therefore share, uniformly:

- the **authorization gate** + per-target **attestation** (the scope note each engine
  writes is belt-and-suspenders only — the server gate is the authority);
- the **findings pipeline**: `ParsedVulnerability.to_finding_fields()` →
  `FindingRepository.create()` with fingerprint **dedup**, a `FINDING_RECORDED` audit
  event, and an SSE trace event per finding;
- the **hybrid verify pass** (`strix_runner.py:1127`, opt-in via
  `settings.strix_verify_pass`): each finding is re-checked by the model profile's
  verify model; a confident CONFIRM promotes `NEW`→`VERIFIED`;
- immutable **audit** events at every lifecycle boundary and cross-container
  **emergency-stop** honoring (DB-status poll in sidecar mode).

### Packaging (the `secops-runner` image)

All engine binaries are baked into `Dockerfile.runner`; the runner has no inbound
network — it polls a DB `run_queue` and drives the Docker socket. `strix image` and
`trivy image` both need the mounted Docker socket. Only **Strix** needs LLM env wiring
(the gateway key + `STRIX_SANDBOX_IMAGE`); every other engine gets a plain
`dict(os.environ)`.

---

## Reference table

| Engine | Scan class | TargetKind(s) | Binary / packaging | Success semantics (`_engine_completed`) | License |
|--------|-----------|---------------|--------------------|------------------------------------------|---------|
| **strix** | Autonomous agent (DAST-depth) | URL, DOMAIN (web); repo-diff via `--scope-mode`| `pip install strix-agent==1.0.4` + Docker sandbox `ghcr.io/usestrix/strix-sandbox:1.0.0` | `run.json` `status == "completed"` (ignores non-zero exit) | verify (usestrix/strix — not stated in-repo) |
| **nuclei** | DAST breadth (templated) | URL, DOMAIN (existing web target) | Go release binary → `/usr/local/bin/nuclei` | exit `== 0` | MIT (ProjectDiscovery) |
| **gitleaks** | Secrets | REPO | Go release binary (rules embedded) | exit `== 0` **or** report produced | MIT |
| **trivy** | SCA / CVE + IaC misconfig + secrets | IMAGE, REPO (+ local `fs`) | Go release binary, DB baked; Docker socket for `trivy image` | exit `== 0` **or** report produced | Apache-2.0 |
| **prowler** | CSPM (cloud posture) | CLOUD_ACCOUNT | isolated venv `/opt/prowler` (`prowler>=5,<6`), symlinked | exit `in (0, 3)` | Apache-2.0 |
| **opengrep** | SAST | REPO | standalone binary → `/opt/opengrep` | exit `== 0` **or** report produced | LGPL (rules are the landmine — see notes) |
| **zap** | DAST (baseline) | URL, DOMAIN | Java JRE + ZAP crossplatform zip → `/opt/zap` (heaviest layer) | exit `in (0, 1, 2)` **or** report produced | Apache-2.0 |
| **naabu** | Port discovery | DOMAIN, IP_RANGE | Go binary + `libpcap` | exit `== 0` | MIT (ProjectDiscovery) |

`TargetKind` enum values live in `app/models/target.py:30-49`
(`DOMAIN`, `URL`, `IP_RANGE`, `REPO`, `IMAGE`, `CLOUD_ACCOUNT`). A `Run` stores targets
as **bare strings**, not typed kinds, so Trivy and Prowler classify the string
heuristically inside `prepare()`.

License go/no-go for all eight was verified 2026-07-09
(`~/Documents/security-ops-engine-licenses-2026-07.md`): the only real landmines are
**rules, not engines** — opengrep-rules (LGPL + Commons-Clause, no-Sell) push toward a
first-party rule pack for SaaS; Trivy's DB mirror + GHSA (CC-BY) + NVD/MITRE strings
carry mandatory attribution.

---

## Per-engine detail

### strix — autonomous offensive agent (default)

- **Purpose / class:** LLM-driven autonomous penetration test; DAST-depth exploitation
  of a web app. The default engine.
- **Targets:** web `URL` / `DOMAIN`; can also run a repo-diff mode
  (`--scope-mode diff --diff-base <sha>`).
- **Invocation** (`build_strix_command`, `strix_runner.py:245`):
  `strix -n -m {quick|standard|deep} -t <t1> [-t <t2> …] --instruction-file <scope> [--scope-mode diff --diff-base <sha>]`.
  Uniquely needs LLM env (`build_strix_env`, `strix_runner.py:195`):
  `STRIX_LLM=openai/<model>`, `LLM_API_BASE` (internal LiteLLM, **direct over
  Tailscale, never Cloudflare**), `LLM_API_KEY`, `STRIX_SANDBOX_IMAGE`, and
  `STRIX_REASONING_EFFORT=none` (the gateway's OpenRouter route rejects it). Runs the
  Docker-sandboxed engine; models come from a **hybrid profile** (cheap local `sweep`
  + stronger `verify`, `MODEL_PROFILES` `strix_runner.py:146`).
- **Parser:** inline `parse_vulnerabilities()` / `_vuln_from_dict` (`strix_runner.py:532`)
  over the **nested** output dir `<run>/strix_runs/<target>_<hash>/vulnerabilities.json`;
  `parse_run_metadata()` reads `run.json` for cost/usage/status; report =
  `penetration_test_report.md`.
- **Success:** `_engine_completed` returns `result.metadata.get("strix_status") == "completed"`
  (`strix_runner.py:979`). Strix **exits non-zero when it finds vulns** (scanner/CI
  convention), so its own `run.json` verdict — not the exit code — is authoritative.
- **License:** usestrix/strix (`strix-agent` on PyPI) — not stated in-repo; **verify**.

### nuclei — templated breadth scanner

- **Purpose / class:** 10k+ community templates for known CVEs/misconfigs; DAST breadth
  beside Strix's depth. Rides the existing web target — no new kind.
- **Targets:** `URL` / `DOMAIN`.
- **Invocation** (`nuclei_runner.py:63`):
  `nuclei -jsonl -output <run>/nuclei.jsonl -no-color -disable-update-check -stats -target <t> …`
  plus per-mode args (`_MODE_ARGS`, `nuclei_runner.py:53`): QUICK =
  `-severity critical,high,medium -rate-limit 150`; STANDARD adds `low`; DEEP = all
  severities at `-rate-limit 100`. No LLM env.
- **Parser:** inline `_parse_nuclei_jsonl` / `_vuln_from_nuclei` (`nuclei_runner.py:140`),
  one finding per JSONL line. (Registry equivalent `NucleiParser` exists but the live
  runner uses the inline one — see `parser-matrix.md`.)
- **Success:** `result.returncode == 0` (`nuclei_runner.py:131`). A clean run exits 0
  with or without findings; non-zero means the scan errored.
- **License:** MIT (ProjectDiscovery).

### gitleaks — repo secret scanner

- **Purpose / class:** hard-coded secrets (keys, tokens, private keys) in the working
  tree **and** commit history. Secrets.
- **Targets:** `REPO` (git URL or local path).
- **Invocation:** `prepare()` builds a `bash -c` script (`_build_gitleaks_command`,
  `gitleaks_runner.py:157`) that per target either uses an existing local dir or
  `git clone`s it, then runs
  `gitleaks detect --source $SRC --report-format json --report-path <run>/gitleaks.<i>.json --no-banner --exit-code 0 --log-level error || true`.
  The clone runs **inside** the subprocess so the cross-container E-stop can interrupt
  it; `--exit-code 0` keeps a leak from looking like a crash.
- **Parser:** inline `_parse_gitleaks_json` / `_vuln_from_gitleaks` (`gitleaks_runner.py:187`)
  over `gitleaks.*.json`. **Redaction is mandatory** — the plaintext `Secret`/`Match` is
  dropped; only rule/file/line/commit metadata and a non-reversible fingerprint
  (`prefix4…(len=N)`, `_redact_secret` `gitleaks_runner.py:214`) reach the Finding.
  Severity fixed HIGH, CWE fixed `CWE-798`.
- **Success:** `returncode == 0` **or** a report was produced (`gitleaks_runner.py:146`)
  — mirrors Nuclei's non-zero-on-match tolerance.
- **License:** MIT.

### trivy — CVE / SCA / IaC / secret scanner

- **Purpose / class:** vulnerable packages (CVEs), IaC misconfigurations, and secrets in
  one binary. SCA (primary) + config + secrets.
- **Targets:** `IMAGE` (new kind, `trivy image`) and `REPO` (`trivy fs` / `trivy repo`);
  the subcommand is chosen per target by `_trivy_target_mode` (`trivy_runner.py:152`) —
  on-disk dir → `fs`, git remote → `repo`, else → `image`.
- **Invocation:** `bash -c` (`_build_trivy_command`, `trivy_runner.py:171`):
  `trivy <mode> --format json --output <run>/trivy.<i>.json --scanners vuln,secret,misconfig <target> || true`.
- **Parser:** inline `_parse_trivy_json` (`trivy_runner.py:192`) walks `Results[]` →
  `{Vulnerabilities, Misconfigurations, Secrets}` (three sub-mappers). Secrets are
  redacted like Gitleaks (`_sanitize_trivy_secret`). `_build_result` is **async** and
  runs `enrich_cves()` (EPSS + CISA KEV, best-effort) when
  `settings.enrichment_enabled` (`trivy_runner.py:125`).
- **Success:** `returncode == 0` **or** report produced (`trivy_runner.py:142`) — Trivy
  doesn't change its exit code on findings unless `--exit-code` is set, which it isn't.
- **License:** Apache-2.0 (DB mirror / GHSA / NVD attribution required).

### prowler — cloud posture (CSPM)

- **Purpose / class:** hundreds of misconfiguration checks across a cloud account. CSPM.
- **Targets:** `CLOUD_ACCOUNT` (`aws:<id>` / `gcp:<project>` / `azure:<subscription>`),
  authorized by the **CLOUD_ROLE** possession proof (assume a scoped role with our
  per-target external ID — `app/authz/cloud_proof.py`), the one genuinely-new gate
  primitive. Single provider per run — the first target sets it (`prowler_runner.py:96`).
- **Invocation** (`prowler_runner.py:82`):
  `prowler <aws|gcp|azure> --output-formats json-ocsf --output-directory <run> --output-filename prowler --status FAIL --no-banner [--verbose if DEEP]`.
  `--status FAIL` means only failing checks become findings; PASS = compliant. Runtime
  cloud creds are a deploy concern (re-assumed role), like Strix's sandbox image.
- **Parser:** inline `parse_prowler_dir` / `_vuln_from_ocsf` (`prowler_runner.py:166`)
  over `*.ocsf.json` (OCSF schema); non-FAIL checks return `None` and are dropped.
  `severity_id` (0-6) maps to a severity band; CWE is `None` (cloud checks map to
  compliance controls, not CWE).
- **Success:** `returncode in (0, 3)` (`prowler_runner.py:157`) — Prowler exits **3**
  when it found failing checks (a successful run with findings), **0** when all pass;
  any other code is a real error (bad creds, etc.).
- **License:** Apache-2.0.

### opengrep — SAST

- **Purpose / class:** static analysis (Semgrep-compatible, the LGPL fork). SAST.
- **Targets:** `REPO` (clone-then-scan, mirrors Gitleaks).
- **Invocation:** `bash -c` (`_build_opengrep_command`, `opengrep_runner.py:114`):
  clone each target, then `opengrep scan --json -o <run>/opengrep.<i>.json --config auto $SRC || true`.
- **Parser:** **registry** — `get_parser("opengrep")` (`opengrep_runner.py:80`), i.e.
  `OpengrepParser` (a relabeled `SemgrepParser`). `_build_result` post-processes each
  finding's evidence (backfills `rule` from `check_id`, stamps `confidence: medium`).
- **Success:** `returncode == 0` **or** report produced (`opengrep_runner.py:110`).
- **License:** LGPL engine (fine server-side); **rules** are the SaaS landmine.

### zap — DAST baseline

- **Purpose / class:** OWASP ZAP baseline scan; deterministic DAST breadth (regulator-
  friendly). One target per invocation by design.
- **Targets:** web `URL` / `DOMAIN`.
- **Invocation:** `bash -c` (`_build_zap_command`, `zap_runner.py:109`):
  `zap-baseline.py -t <target> -J <run>/zap.<i>.json -I || true` per target.
- **Parser:** **registry** — `get_parser("zap")` (`zap_runner.py:77`), i.e. `ZapParser`
  (native `site[].alerts[]` JSON, or SARIF); stamps `confidence: medium`.
- **Success:** `returncode in (0, 1, 2)` **or** report produced (`zap_runner.py:105`) —
  ZAP baseline uses 0/1/2 for "warnings/failures present" outcomes that are still a
  completed scan.
- **License:** Apache-2.0.

### naabu — port discovery

- **Purpose / class:** fast TCP port discovery. Emits one **INFO** finding per open
  port. Port scan.
- **Targets:** `DOMAIN`, `IP_RANGE` (authorized domain ≠ authorized CIDR — scope must
  name the range explicitly).
- **Invocation:** `bash -c` (`_build_naabu_command`, `naabu_runner.py:99`):
  `naabu -host <target> -json -o <run>/naabu.<i>.jsonl -silent || true` per target.
- **Parser:** inline `_parse_naabu_jsonl` / `_vuln_from_naabu` (`naabu_runner.py:109`),
  one INFO finding per JSONL row (`host:port` endpoint, severity `INFO`, no CWE).
- **Success:** `returncode == 0` (`naabu_runner.py:95`).
- **License:** MIT (ProjectDiscovery).
