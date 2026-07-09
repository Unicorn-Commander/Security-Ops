"""Prowler OCSF parsing + the ProwlerRunner seams (engine #5, CSPM).

Prowler emits OCSF detection findings; only FAIL checks are vulnerabilities (PASS =
compliant). These tests pin the parser (FAIL→finding, PASS→skip, severity mapping,
evidence capture) and the two behavioral seams (command build, exit-code interpretation)
without needing the real ``prowler`` binary or a live cloud account.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.engine.prowler_runner import (
    ProwlerRunner,
    _provider_account,
    _vuln_from_ocsf,
    parse_prowler_dir,
)
from app.engine.strix_runner import StrixRunResult
from app.models.finding import FindingSeverity


def _fail_finding():
    return {
        "status_code": "FAIL",
        "severity": "High",
        "finding_info": {"title": "S3 bucket allows public read", "desc": "Bucket ACL grants READ to AllUsers"},
        "metadata": {"event_code": "s3_bucket_public_access"},
        "resources": [{"uid": "arn:aws:s3:::my-bucket", "name": "my-bucket", "type": "AwsS3Bucket"}],
        "remediation": {"desc": "Remove the public grant", "references": ["https://docs.aws.amazon.com/s3"]},
        "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1"},
    }


def _pass_finding():
    return {
        "status_code": "PASS",
        "severity": "High",
        "finding_info": {"title": "S3 bucket is private"},
        "metadata": {"event_code": "s3_bucket_public_access"},
    }


def test_fail_finding_maps_to_vulnerability():
    v = _vuln_from_ocsf(_fail_finding())
    assert v is not None
    assert v.title == "S3 bucket allows public read"
    assert v.severity == FindingSeverity.HIGH
    assert v.endpoint == "arn:aws:s3:::my-bucket"
    assert v.evidence["check_id"] == "s3_bucket_public_access"
    assert v.evidence["account"] == "123456789012"
    assert v.evidence["remediation"] == "Remove the public grant"


def test_pass_finding_is_not_a_vulnerability():
    assert _vuln_from_ocsf(_pass_finding()) is None


def test_severity_from_id_when_string_absent():
    v = _vuln_from_ocsf({"status_code": "FAIL", "severity_id": 5, "finding_info": {"title": "x"}})
    assert v.severity == FindingSeverity.CRITICAL


def test_unknown_severity_defaults_medium():
    v = _vuln_from_ocsf({"status_code": "FAIL", "finding_info": {"title": "x"}})
    assert v.severity == FindingSeverity.MEDIUM


def test_parse_prowler_dir_reads_ocsf(tmp_path: Path):
    (tmp_path / "prowler.ocsf.json").write_text(json.dumps([_fail_finding(), _pass_finding()]), encoding="utf-8")
    findings = parse_prowler_dir(tmp_path)
    assert len(findings) == 1  # only the FAIL
    assert findings[0].title == "S3 bucket allows public read"


def test_parse_prowler_dir_missing_is_empty(tmp_path: Path):
    assert parse_prowler_dir(tmp_path / "nope") == []


def test_provider_account_split():
    assert _provider_account("aws:123456789012") == ("aws", "123456789012")
    assert _provider_account("gcp:my-project") == ("gcp", "my-project")
    assert _provider_account("azure:sub-guid") == ("azure", "sub-guid")
    # bare/mis-shaped value falls back to an AWS scan rather than crashing the seam
    assert _provider_account("bare-value")[0] == "aws"


def test_engine_completed_accepts_findings_exit_code():
    r = ProwlerRunner(session=None)  # type: ignore[arg-type]
    assert r._engine_completed(StrixRunResult(returncode=0, findings=[], metadata={}, report_path=None)) is True
    assert r._engine_completed(StrixRunResult(returncode=3, findings=[], metadata={}, report_path=None)) is True
    assert r._engine_completed(StrixRunResult(returncode=1, findings=[], metadata={}, report_path=None)) is False
