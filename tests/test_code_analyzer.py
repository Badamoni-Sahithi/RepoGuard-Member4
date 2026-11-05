
import pytest
from app.code_analyzer import analyze_code


def test_invalid_repository_path():
    with pytest.raises(ValueError):
        analyze_code("folder_that_does_not_exist_12345")


def test_code_analyzer_returns_list():
    result = analyze_code("test-repo")

    assert isinstance(result, list)


def test_findings_have_required_fields():
    findings = analyze_code("test-repo")

    required_fields = [
        "type",
        "rule_id",
        "description",
        "file",
        "line",
        "severity",
        "source",
    ]

    for finding in findings:
        for field in required_fields:
            assert field in finding