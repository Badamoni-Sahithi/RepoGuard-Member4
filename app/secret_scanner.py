
import json
import subprocess
from pathlib import Path


def scan_secrets(repo_path: str) -> list[dict]:
    """
    Scan a repository directory using Gitleaks.
    Secret values are never exposed in the results.
    """

    repository = Path(repo_path).resolve()

    if not repository.exists() or not repository.is_dir():
        raise ValueError("Repository directory does not exist.")

    command = [
        "gitleaks",
        "dir",
        str(repository),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
        "--redact=100",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            check=False,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("Gitleaks scan timed out.")

    except FileNotFoundError:
        raise RuntimeError("Gitleaks is not installed or not in PATH.")

    # Exit code 0: no findings
    # Exit code 1: findings detected
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Gitleaks failed: {result.stderr[:500]}"
        )

    try:
        raw_findings = json.loads(result.stdout or "[]")

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Could not parse Gitleaks JSON report."
        ) from exc

    findings = []

    for item in raw_findings:

        findings.append({
            "type": "SECRET",
            "rule_id": item.get("RuleID", "unknown"),
            "description": item.get(
                "Description",
                "Potential secret detected"
            ),
            "file": item.get("File", "unknown"),
            "line": item.get("StartLine"),
            "severity": "HIGH",
            "secret": "[REDACTED]",
            "source": "Gitleaks",
        })

    print("Secret scanning completed!")
    print(f"Potential secrets found: {len(findings)}")

    return findings