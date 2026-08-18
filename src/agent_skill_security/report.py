from datetime import datetime
from pathlib import Path


def generate_report(results) -> str:
    """
    Generate Agent Skill Security Report.
    """

    if not isinstance(results, dict):
        results = {}

    target = results.get("target", "unknown")
    findings = results.get("findings", [])
    risk = results.get("risk", {})

    score = risk.get("risk_score", 0)
    level = risk.get("risk_level", "LOW")

    # 统计实际出现安全发现的不同文件
    unique_files = {
        str(item.get("file"))
        for item in findings
        if isinstance(item, dict) and item.get("file")
    }

    # 当前 Dashboard 也是按照实际发现文件统计
    if unique_files:
        files_scanned = len(unique_files)
    else:
        files_scanned = results.get("files_scanned", 0)

    lines = []

    lines.append("=" * 60)
    lines.append("Agent Skill Security Report")
    lines.append("=" * 60)

    lines.append(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append(
        f"Target: {target}"
    )

    lines.append("")

    # =========================
    # STATUS
    # =========================

    if findings:
        lines.append("Status: SECURITY ISSUES FOUND")
    else:
        lines.append("Status: SAFE")

    lines.append("")

    # =========================
    # SUMMARY
    # =========================

    lines.append("=" * 60)
    lines.append("Scan Summary")
    lines.append("=" * 60)

    lines.append(
        f"Files Scanned: {files_scanned}"
    )

    lines.append(
        f"Total Findings: {len(findings)}"
    )

    lines.append(
        f"Overall Risk Score: {score}/100"
    )

    lines.append(
        f"Overall Risk Level: {level}"
    )

    lines.append("")

    # =========================
    # GROUP FINDINGS BY FILE
    # =========================

    grouped_findings = {}

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        file_path = finding.get(
            "file",
            "unknown"
        )

        if file_path not in grouped_findings:
            grouped_findings[file_path] = []

        grouped_findings[file_path].append(
            finding
        )

    # =========================
    # SECURITY FINDINGS
    # =========================

    lines.append("=" * 60)
    lines.append("Security Findings")
    lines.append("=" * 60)

    if not grouped_findings:

        lines.append("")
        lines.append(
            "No security issues found."
        )

    else:

        for file_path, file_findings in grouped_findings.items():

            lines.append("")
            lines.append("-" * 60)

            try:
                file_name = Path(file_path).name
            except Exception:
                file_name = str(file_path)

            lines.append(
                f"File: {file_name}"
            )

            lines.append(
                f"Path: {file_path}"
            )

            lines.append(
                f"Issues Found: {len(file_findings)}"
            )

            lines.append("")

            for index, finding in enumerate(
                file_findings,
                start=1
            ):

                category = (
                    finding.get("category")
                    or finding.get("type")
                    or "unknown"
                )

                severity = finding.get(
                    "severity",
                    "unknown"
                )

                match = (
                    finding.get("match")
                    or finding.get("pattern")
                    or "detected"
                )

                lines.append(
                    f"{index}. [{severity.upper()}] {category}"
                )

                lines.append(
                    f"   Detected: {match}"
                )

                lines.append(
                    f"   Recommendation: {get_recommendation(category)}"
                )

                lines.append("")

    # =========================
    # CATEGORY SUMMARY
    # =========================

    categories = {}

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        category = (
            finding.get("category")
            or finding.get("type")
            or "unknown"
        )

        categories[category] = (
            categories.get(category, 0) + 1
        )

    lines.append("")
    lines.append("=" * 60)
    lines.append("Vulnerability Categories")
    lines.append("=" * 60)

    if categories:

        for category, count in categories.items():

            lines.append(
                f"- {category}: {count}"
            )

    else:

        lines.append("- None")

    # =========================
    # GENERAL RECOMMENDATIONS
    # =========================

    lines.append("")
    lines.append("=" * 60)
    lines.append("General Recommendations")
    lines.append("=" * 60)

    if findings:

        lines.append(
            "- Remove hardcoded secrets and API keys."
        )

        lines.append(
            "- Restrict AI agent and automation tool permissions."
        )

        lines.append(
            "- Validate and sanitize external inputs."
        )

        lines.append(
            "- Review shell command execution."
        )

        lines.append(
            "- Review outbound network requests."
        )

        lines.append(
            "- Protect system prompts from prompt injection."
        )

    else:

        lines.append(
            "- No immediate security issues detected."
        )

        lines.append(
            "- Continue regular security scanning."
        )

    lines.append("")
    lines.append("=" * 60)
    lines.append("End of Report")
    lines.append("=" * 60)

    return "\n".join(lines)


def get_recommendation(category: str) -> str:

    recommendations = {

        "hardcoded_api_key":
            "Remove the hardcoded API key and use environment variables or a secure secret manager.",

        "secret_exposure":
            "Remove exposed credentials or tokens and rotate compromised credentials.",

        "dangerous_shell":
            "Avoid unrestricted shell execution and restrict commands to an explicit allowlist.",

        "dangerous_code":
            "Review dynamic code execution and remove unsafe eval, exec, or subprocess behavior.",

        "file_system_write":
            "Restrict file system write permissions and validate destination paths.",

        "prompt_injection":
            "Separate trusted instructions from untrusted content and validate tool actions before execution.",

        "network_request":
            "Restrict outbound network access and validate destination domains and request parameters.",
    }

    return recommendations.get(
        category,
        "Review this finding manually and restrict the affected capability."
    )