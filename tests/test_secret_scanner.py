
import pytest
from app.secret_scanner import scan_secrets


def test_invalid_repository_path():
    with pytest.raises(ValueError):
        scan_secrets("folder_that_does_not_exist_12345")


def test_secret_scanner_returns_list():
    result = scan_secrets("test-repo")

    assert isinstance(result, list)


def test_secret_values_are_redacted():
    findings = scan_secrets("test-repo")

    for finding in findings:
        assert finding["secret"] == "[REDACTED]"