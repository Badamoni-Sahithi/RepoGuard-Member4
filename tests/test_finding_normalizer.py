
from app.finding_normalizer import (
    normalize_severity,
    normalize_findings,
)


def test_severity_mapping():
    assert normalize_severity("ERROR") == "HIGH"
    assert normalize_severity("WARNING") == "MEDIUM"
    assert normalize_severity("INFO") == "LOW"
    assert normalize_severity("CRITICAL") == "CRITICAL"


def test_finding_normalization():
    sample = [
        {
            "type": "CODE_ISSUE",
            "rule_id": "test-rule",
            "description": "Example security finding",
            "file": "example.py",
            "line": 10,
            "severity": "ERROR",
            "source": "Semgrep",
        }
    ]

    result = normalize_findings(sample)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
    assert result[0]["source"] == "Semgrep"
    assert result[0]["file"] == "example.py"
    assert result[0]["line"] == 10