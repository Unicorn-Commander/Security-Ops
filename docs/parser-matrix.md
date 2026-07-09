# Engine ↔ parser ↔ Finding matrix

`app/engine/parsers/` is a **DefectDojo-style, tool-agnostic finding normalizer**. Its
goal (stated in `parsers/__init__.py`) is to make adding a scanner "wire a CLI + point
at a parser" instead of "hand-write a JSON→Finding normalizer". This doc maps each
engine to its normalization path and to the canonical `Finding` fields it populates.

> **Provenance:** the intermediate shape and the "one small parser per tool feeding a
> common normalizer" architecture are modeled on DefectDojo
> (`DefectDojo/django-DefectDojo`, **BSD-3-Clause**). This is an original
> re-implementation of the *approach* — none of DefectDojo's Django code is vendored
> (`parsers/base.py:17-22`).

## The contract: `Parser` / `DojoFinding` → `ParsedVulnerability` → `Finding`

Two shapes in `parsers/base.py` make the corpus work:

- **`DojoFinding`** (`base.py:178`) — the DefectDojo-style intermediate. It carries the
  **superset** of fields DefectDojo normalizes onto: `title`, `severity`, `endpoint`,
  `cwe`, `cve`, `cvssv3`/`cvssv3_score`, `epss_score`/`epss_percentile`, `file_path`,
  `line`, `component_name`/`component_version`, `references`, `tags`,
  `unique_id_from_tool`/`vuln_id_from_tool`, `endpoints`, plus a per-tool
  `evidence_extra` bag and `raw`. A concrete parser's only job is to translate its
  tool's native JSON into a `list[DojoFinding]`.
- **`Parser`** (ABC, `base.py:286`) — every parser implements
  `parse_findings(report) -> list[DojoFinding]`; the shared `Parser.parse()` maps those
  to `list[ParsedVulnerability]` (stamping the engine label onto blank `tool` values).

`DojoFinding.to_parsed_vulnerability()` (`base.py:250`) collapses the intermediate to a
`ParsedVulnerability`: it funnels every superset field that has **no first-class
`ParsedVulnerability` home** (description, mitigation, cve, cvss, epss, file/line,
component, references, tool ids, extra endpoints, `evidence_extra`) into the
`evidence` dict under stable keys (`_EVIDENCE_KEYS`, `base.py:231`), drops `None`s
(`raw` always kept), and normalizes severity + CWE on the way out.

`ParsedVulnerability` (defined in `strix_runner.py:357`) is the canonical internal shape
the persistence layer writes. `to_finding_fields()` (`strix_runner.py:370`) maps it to a
`Finding` row (`app/models/finding.py:47`):

| `Finding` column | Source | Notes |
|------------------|--------|-------|
| `title` | `ParsedVulnerability.title` | required |
| `severity` | `.severity` | `FindingSeverity` enum; unknown/missing → `MEDIUM` |
| `cwe` | `.cwe` | the **only** classification with a first-class column (`String(64)`) |
| `endpoint` | `.endpoint` | free-form locus (URL, `file:line`, `pkg@ver`, `host:port`) |
| `fingerprint` | computed | `_finding_fingerprint(...)` — dedup key, see below |
| `payload` | `.payload` | e.g. Nuclei curl / Trivy upgrade hint; **never** a raw secret |
| `poc` | `.poc` | proof / location ref |
| `evidence` | `.evidence` | JSONB — carries `engine`, `cve`, `cvssv3`, `epss`, `raw`, and everything funneled from `DojoFinding` |
| `verified_by` | runner arg | sweep-model label, later overwritten by verify model |
| `status` | constant | `FindingStatus.NEW` |

**`cve` is NOT a column** — it (and cvss/epss/references/component) live inside
`evidence`. Only `cwe` is promoted to a first-class field.

### Fingerprint = the cross-engine dedup key

`_finding_fingerprint(engine, cwe_or_cve, endpoint, title)` (`strix_runner.py:461`)
hashes `sha256("<cwe_or_cve>|<endpoint>|<title>")[:64]` on **normalized** (lower-cased,
whitespace-collapsed) text. Note the `engine` argument is accepted but **deliberately
not part of the hashed material** — so the same weakness found by two engines
fingerprints identically, and `FindingRepository.create()` dedups it across engines
(`cwe_or_cve` falls back to `evidence["cve"]` when there's no CWE, `strix_runner.py:376`).

## Shared parsers

| Module | Class | Role |
|--------|-------|------|
| `parsers/base.py` | `Parser`, `DojoFinding` | the contract + normalization primitives (`normalize_severity`, `normalize_cwe`, `first_scalar`, `load_report`, `iter_jsonl`) |
| `parsers/generic.py` | `GenericParser` | permissive fallback — DefectDojo "Generic Findings Import" (`{"findings":[…]}` or bare array). The "no bespoke parser needed" escape hatch. **Does not redact** — never point at raw secret output |
| `parsers/sarif.py` | `SarifParser` | SARIF 2.1.0 — walks `runs[].results[]`, resolves rule metadata by `ruleId`/`ruleIndex`, bands numeric `security-severity` (0-10) or maps `level`. The common denominator for Opengrep/Semgrep/ZAP/CodeQL |
| `parsers/semgrep.py` | `SemgrepParser` | Semgrep native JSON (`{"results":[…]}`) **or** SARIF (auto-detected via a `runs` key, delegated to `parse_sarif`) |

**SARIF is the shared backbone.** `SemgrepParser`, `OpengrepParser`, and `ZapParser`
all delegate a `{"runs":[…]}` document to `parse_sarif()` — so any SARIF-capable tool
can reuse one mapper. `OpengrepParser` (`parsers/opengrep.py`) is literally a subclass
of `SemgrepParser` that only overrides `tool = "opengrep"` (identical field maps, just a
different engine label).

## `get_parser()` resolution

`get_parser(tool)` (`parsers/__init__.py:56`) does
`PARSERS.get(tool.strip().lower())`, returning `None` for an unknown tool (so a caller
can fall back to `get_parser("generic")`). The registry `PARSERS`
(`parsers/__init__.py:42`):

```
nuclei → NucleiParser      trivy  → TrivyParser      gitleaks → GitleaksParser
sarif  → SarifParser       semgrep→ SemgrepParser    opengrep → OpengrepParser
zap    → ZapParser         generic→ GenericParser
aliases:  trivy-secrets → TrivyParser    owasp-zap → ZapParser
```

Parsers are stateless singletons. Note there is **no `strix`, `prowler`, or `naabu`**
entry — those engines parse inline (see the caveat below).

## The matrix

| Engine | Normalization path (as wired) | Input format | Key `Finding` fields populated |
|--------|-------------------------------|--------------|--------------------------------|
| **strix** | inline `parse_vulnerabilities` / `_vuln_from_dict` (`strix_runner.py:532`) | `vulnerabilities.json` (list or `{vulnerabilities:[…]}`) + `run.json` | severity, cwe, endpoint, title, payload, poc, fingerprint, evidence(raw+cve+desc+remediation) |
| **nuclei** | inline `_parse_nuclei_jsonl` / `_vuln_from_nuclei` (`nuclei_runner.py:140`) | JSONL (one obj/line) | severity, cwe (`classification.cwe-id`), endpoint (`matched-at`), title, payload (`curl-command`), poc, fingerprint, evidence(template_id, cve, tags) |
| **gitleaks** | inline `_parse_gitleaks_json` / `_vuln_from_gitleaks` (`gitleaks_runner.py:187`) | JSON array of leaks | severity=**HIGH** (fixed), cwe=**CWE-798** (fixed), endpoint (`file:line`), title, poc (location id), fingerprint, evidence(**redacted** secret fp, commit/author) |
| **trivy** | inline `_parse_trivy_json` + 3 sub-mappers (`trivy_runner.py:192`); async `enrich_cves` (EPSS/KEV) | JSON `{Results:[{Vulnerabilities,Misconfigurations,Secrets}]}` | severity, cwe (`CweIDs`; secrets **CWE-798**; misconfig none), endpoint (`pkg@ver` / target / `target:line`), title, payload (upgrade hint), fingerprint, evidence(pkg, fixed, epss, kev, **redacted** secret) |
| **prowler** | inline `parse_prowler_dir` / `_vuln_from_ocsf` (`prowler_runner.py:166`) | OCSF JSON (`*.ocsf.json`) | severity (from string/`severity_id`), cwe=**None**, endpoint (resource uid), title, poc (`status_detail`), fingerprint, evidence(check_id, account, region, compliance); FAIL-only |
| **opengrep** | **registry** `get_parser("opengrep")` → `OpengrepParser`(`SemgrepParser`) (`opengrep_runner.py:80`) | Semgrep native JSON **or** SARIF | severity (lint-level band), cwe (`metadata.cwe`), endpoint (`file:line`), title, fingerprint, evidence(check_id, rule, confidence=medium) |
| **zap** | **registry** `get_parser("zap")` → `ZapParser` (`zap_runner.py:77`) | native `{site[].alerts[]}` **or** SARIF | severity (`riskcode` 0-3), cwe (`cweid`), endpoint (first instance URI), title, mitigation→evidence, endpoints[], fingerprint, evidence(plugin_id, confidence=medium) |
| **naabu** | inline `_parse_naabu_jsonl` / `_vuln_from_naabu` (`naabu_runner.py:109`) | JSONL | severity=**INFO** (fixed), cwe=None, endpoint (`host:port`), title (`Open port …`), fingerprint, evidence(host, ip, port) |

## ⚠️ Accuracy caveat: registry-wired vs inline

The `parsers/` corpus and the live runners are **not fully unified**. Which path an
engine actually uses today:

- **Registry-wired** (call `get_parser(...)` in `_build_result`): **opengrep**, **zap**.
- **Inline hand-rolled** (own `_parse_*` / `_vuln_from_*`, do **not** touch the
  registry): **strix**, **nuclei**, **gitleaks**, **trivy**, **prowler**, **naabu**.

Critically, the registry **does** ship `NucleiParser`, `TrivyParser`, and
`GitleaksParser`, but the corresponding runners still use their inline parsers. These
registry versions are proven-equivalent stand-ins: `parsers/base.py:44-50` states the
runner migration is "deliberately NOT done here to avoid regressing the live runners,"
and `tests/test_parsers_defectdojo.py` pins that `get_parser("nuclei"|"trivy"|"gitleaks")`
emits an **identical** `list[ParsedVulnerability]` to the inline runner. So a future
runner can drop its `_parse_*` helpers and switch to `get_parser(...)` with no behavior
change — but until then, **editing a registry parser for nuclei/trivy/gitleaks does not
change what those runners produce.** The redaction helpers (`_redact_secret`,
`_sanitize_gitleaks_item`, `_sanitize_trivy_secret`) are single-sourced in the runners
and imported by both paths, so secret-safety holds either way.

The registry also carries `sarif`, `semgrep`, and `generic` parsers that **no engine
wires directly** — `sarif`/`semgrep` are shared machinery (Opengrep/ZAP delegate to
them for SARIF input; Opengrep subclasses Semgrep), and `generic` is the escape hatch
for a future tool that emits the DefectDojo import shape.
