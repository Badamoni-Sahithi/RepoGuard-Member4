
def normalize_severity(value: str) -> str:

    value = (value or "UNKNOWN").upper()

    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "MODERATE": "MEDIUM",
    }

    if value in mapping:
        return mapping[value]

    if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return value

    return "UNKNOWN"


def normalize_findings(findings: list[dict]) -> list[dict]:

    normalized = []

    for finding in findings:

        normalized.append({
            "type": finding.get("type", "UNKNOWN"),

            "rule_id": finding.get(
                "rule_id", "unknown"
            ),

            "description": finding.get(
                "description",
                "No description available"
            ),

            "file": finding.get("file", "unknown"),

            "line": finding.get("line"),

            "severity": normalize_severity(
                finding.get("severity")
            ),

            "source": finding.get("source", "unknown"),
        })

    return normalized