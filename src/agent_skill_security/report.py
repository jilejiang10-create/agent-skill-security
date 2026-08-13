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


    total_risk = 0
    
    
    if isinstance(results, dict):
        results = [results]
    
    
        for data in results:
        
            if not isinstance(data, dict):
                continue
        
            file_name = (
                data.get("file")
                or data.get("path")
                or "unknown"
            ) 
            if file_name == "unknown":
                file_name = data.get("path", "unknown")
            risk = data.get("risk", {})
        
            if isinstance(risk, dict):
                risk_score = risk.get("risk_score", 0)
            else:
                risk_score = 0
        
            total_risk += risk_score
        
        
            lines.append(
                f"File: {file_name}"
            )
        


        lines.append(
            f"Risk Score: {risk_score}/100"
        )

        seen = set()
        
        for finding in data.get("findings", []):
        
            if isinstance(finding, dict):
        
                category = (
                    finding.get("category")
                    or finding.get("type")
                    or "unknown"
                )
        
                match = finding.get("match", "")
        
                item = f"{category}: {match}"
        
                if item not in seen:
                    seen.add(item)
        
                    lines.append(
                        f"- {item}"
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
