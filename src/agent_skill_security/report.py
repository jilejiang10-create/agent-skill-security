from datetime import datetime


def generate_report(results):

    lines = []


    lines.append("=" * 50)
    lines.append("Agent Skill Security Report")
    lines.append("=" * 50)


    lines.append(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )


    lines.append("")


    if isinstance(results, dict):

        results = [results]



    total_files = 0
    total_findings = 0

    max_score = 0
    max_level = "LOW"



    lines.append(
        "Status: SECURITY ISSUES FOUND"
    )

    lines.append("")

    lines.append(
        "Findings"
    )

    lines.append(
        "-" * 50
    )



    for data in results:


        if not isinstance(data, dict):

            continue



        total_files += 1



        file_name = (
            data.get("target")
            or data.get("file")
            or "unknown"
        )


        # 正确读取 scanner.py 的 risk

        risk = data.get(
            "risk",
            {}
        )


        score = risk.get(
            "risk_score",
            0
        )


        level = risk.get(
            "risk_level",
            "UNKNOWN"
        )



        if score > max_score:

            max_score = score
            max_level = level



        lines.append("")

        lines.append(
            f"File: {file_name}"
        )


        lines.append(
            f"Risk: {score}/100 ({level})"
        )



        findings = data.get(
            "findings",
            []
        )


        for item in findings:


            if not isinstance(item, dict):

                continue



            total_findings += 1



            lines.append(
                f"- [{item.get('severity','unknown')}] "
                f"{item.get('category','unknown')}: "
                f"{item.get('match','detected')}"
            )



    lines.append("")

    lines.append(
        "-" * 50
    )


    lines.append(
        f"Files Scanned: {total_files}"
    )


    lines.append(
        f"Total Findings: {total_findings}"
    )


    lines.append(
        f"Overall Risk Score: {max_score}/100"
    )


    lines.append(
        f"Overall Risk Level: {max_level}"
    )


    return "\n".join(lines)