from datetime import datetime


def generate_report(results: list) -> str:
    """
    Generate security scan report
    """

    lines = []

    lines.append("=" * 40)
    lines.append("Agent Security Report")
    lines.append("=" * 40)

    lines.append(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append("")

    if not results:
        lines.append("Status: SAFE")
        lines.append("No security issues found.")
        return "\n".join(lines)


    total_risk = 0

    lines.append("Status: ISSUES FOUND")
    lines.append("")

    lines.append("Findings:")
    lines.append("-" * 40)


    for data in results:

        risk = data.get("risk", 0) if isinstance(data, dict) else 0

        total_risk += risk

        lines.append(
        f"File: {data}"
)

        lines.append(
            f"Risk Score: {risk}/100"
        )

        for finding in data.get("findings", []):

            lines.append(
                f"- {finding.get('category')}: "
                f"{finding.get('match')}"
            )


    avg_risk = min(total_risk, 100)


    lines.append("")
    lines.append("-" * 40)

    lines.append(
        f"Overall Risk Score: {avg_risk}/100"
    )


    if avg_risk >= 80:
        level = "CRITICAL"

    elif avg_risk >= 50:
        level = "HIGH"

    elif avg_risk >= 20:
        level = "MEDIUM"

    else:
        level = "LOW"


    lines.append(
        f"Risk Level: {level}"
    )


    lines.append("")
    lines.append("Recommendations:")

    lines.append(
        "- Remove hardcoded secrets"
    )

    lines.append(
        "- Validate user inputs"
    )

    lines.append(
        "- Review agent tools permissions"
    )


    return "\n".join(lines)
