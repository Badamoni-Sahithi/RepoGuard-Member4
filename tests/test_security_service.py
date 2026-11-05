
from app.security_service import run_security_analysis


def test_security_analysis_returns_dictionary():
    result = run_security_analysis("test-repo")

    assert isinstance(result, dict)


def test_security_analysis_has_required_fields():
    result = run_security_analysis("test-repo")

    assert "secret_findings" in result
    assert "code_findings" in result
    assert "total_findings" in result
    assert "severity_counts" in result
    assert "findings" in result
    assert result["status"] == "completed"


def test_total_findings_count():
    result = run_security_analysis("test-repo")

    assert result["total_findings"] == len(result["findings"])