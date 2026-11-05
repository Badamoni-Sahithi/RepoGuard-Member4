
from app.secret_scanner import scan_secrets
from app.code_analyzer import analyze_code
from app.finding_normalizer import normalize_findings


def run_security_analysis(repo_path: str) -> dict:
    """
    Run secret scanning and static code analysis.
    Combine and normalize all findings.
    """

    secret_findings = scan_secrets(repo_path)

    code_findings = analyze_code(repo_path)

    all_findings = (
        secret_findings + code_findings
    )

    findings = normalize_findings(all_findings)

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in findings:

        severity = finding["severity"]

        counts[severity] += 1

    return {
        "secret_findings": len(secret_findings),

        "code_findings": len(code_findings),

        "total_findings": len(findings),

        "severity_counts": counts,

        "findings": findings,

        "status": "completed",
    }