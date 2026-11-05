
import json
import subprocess
from pathlib import Path


def analyze_code(repo_path: str) -> list[dict]:
    """
    Analyze source code using Semgrep.
    Returns potential security findings.
    """

    repository = Path(repo_path).resolve()

    if not repository.exists() or not repository.is_dir():
        raise ValueError("Repository directory does not exist.")

    semgrep_python = (
        Path.home()
        / "AppData"
        / "Local"
        / "pipx"
        / "pipx"
        / "venvs"
        / "semgrep"
        / "Scripts"
        / "python.exe"
    )

    if not semgrep_python.is_file():
        raise RuntimeError("Isolated Semgrep Python not found.")

    command = [
        str(semgrep_python),
        "-c",
        "import sys; from semgrep.console_scripts.pysemgrep import main; sys.argv=['semgrep', *sys.argv[1:]]; main()",
        "scan",
        "--config",
        "p/default",
        "--json",
        "--metrics=off",
        str(repository),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
            shell=False,
            check=False,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("Semgrep scan timed out.")

    except FileNotFoundError:
        raise RuntimeError("Semgrep executable not found.")

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed: {result.stderr[:500]}"
        )

    try:
        report = json.loads(result.stdout)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Could not parse Semgrep JSON report."
        ) from exc

    findings = []

    for item in report.get("results", []):
        extra = item.get("extra", {})

        findings.append({
            "type": "CODE_ISSUE",
            "rule_id": item.get("check_id", "unknown"),
            "description": extra.get(
                "message",
                "Potential code security issue"
            ),
            "file": item.get("path", "unknown"),
            "line": item.get("start", {}).get("line"),
            "severity": extra.get(
                "severity", "INFO"
            ).upper(),
            "source": "Semgrep",
        })

    print("Code analysis completed!")
    print(f"Potential issues found: {len(findings)}")

    return findings