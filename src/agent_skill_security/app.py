import json
import html
import streamlit as st
from pathlib import Path
from datetime import datetime

from agent_skill_security.scanner import scan_directory
from agent_skill_security.report import generate_report


st.set_page_config(
    page_title="Agent Skill Security",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ Agent Skill Security")

st.write(
    "AI Agent / Plugin / Automation Script Security Scanner"
)

st.divider()


default_path = str(
    Path(__file__).resolve()
    .parent.parent.parent
    / "tests"
    / "malicious_samples"
)


target = st.text_input(
    "Target project path",
    default_path
)


def get_recommendation(category: str) -> str:

    recommendations = {

        "hardcoded_api_key":
            "Remove the hardcoded API key and use environment variables or a secure secret manager.",

        "secret_exposure":
            "Remove exposed credentials or tokens and rotate any credentials that may have been compromised.",

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


def build_html_report(results, report_text):

    risk = results.get(
        "risk",
        {}
    )

    score = risk.get(
        "risk_score",
        0
    )

    level = risk.get(
        "risk_level",
        "LOW"
    )

    target_path = results.get(
        "target",
        "unknown"
    )

    generated = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    safe_report = html.escape(
        report_text
    )

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>Agent Skill Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    max-width: 1100px;
    margin: 40px auto;
    padding: 20px;
    line-height: 1.6;
}}

h1 {{
    margin-bottom: 5px;
}}

.summary {{
    display: flex;
    gap: 20px;
    margin: 30px 0;
}}

.card {{
    flex: 1;
    border: 1px solid #ddd;
    border-radius: 10px;
    padding: 20px;
}}

pre {{
    background: #f5f5f5;
    padding: 20px;
    border-radius: 10px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}}

.critical {{
    color: #b00020;
    font-weight: bold;
}}

</style>

</head>

<body>

<h1>🛡️ Agent Skill Security</h1>

<p>AI Agent / Plugin / Automation Script Security Scanner</p>

<hr>

<p><strong>Generated:</strong> {generated}</p>

<p><strong>Target:</strong> {html.escape(str(target_path))}</p>

<div class="summary">

<div class="card">
<h3>Risk Score</h3>
<p>{score}/100</p>
</div>

<div class="card">
<h3>Risk Level</h3>
<p class="critical">{html.escape(str(level))}</p>
</div>

</div>

<h2>Security Report</h2>

<pre>{safe_report}</pre>

</body>

</html>
"""


if st.button("Start Security Scan"):

    with st.spinner("Scanning..."):

        try:

            results = scan_directory(
                target
            )

            report = generate_report(
                results
            )

            findings = results.get(
                "findings",
                []
            )

            files_scanned = len(
                set(
                    item.get("file")
                    for item in findings
                    if isinstance(item, dict)
                    and item.get("file")
                )
            )

            if not files_scanned:

                files_scanned = results.get(
                    "files_scanned",
                    0
                )

            risk = results.get(
                "risk",
                {}
            )

            score = risk.get(
                "risk_score",
                0
            )

            level = risk.get(
                "risk_level",
                "LOW"
            )

            st.success(
                "Scan completed"
            )


            # =========================
            # Scan Summary
            # =========================

            st.subheader(
                "🛡️ Scan Summary"
            )

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "Files Scanned",
                files_scanned
            )

            c2.metric(
                "Total Findings",
                len(findings)
            )

            c3.metric(
                "Risk Score",
                f"{score}/100"
            )

            st.divider()

            c4, c5 = st.columns(2)

            c4.metric(
                "Risk Level",
                level
            )

            if level == "CRITICAL":

                c5.error(
                    "Critical security risk detected"
                )

            elif level == "HIGH":

                c5.warning(
                    "High security risk detected"
                )

            elif level == "MEDIUM":

                c5.warning(
                    "Medium security risk detected"
                )

            else:

                c5.success(
                    "Risk level acceptable"
                )


            # =========================
            # Vulnerability Categories
            # =========================

            st.subheader(
                "🔍 Vulnerability Categories"
            )

            categories = {}

            for item in findings:

                if not isinstance(item, dict):
                    continue

                category = (
                    item.get("category")
                    or item.get("type")
                    or "unknown"
                )

                categories[category] = (
                    categories.get(category, 0) + 1
                )

            if categories:

                for category, count in categories.items():

                    st.write(
                        f"• {category}: {count}"
                    )

            else:

                st.write(
                    "No vulnerability categories detected."
                )

            st.divider()


            # =========================
            # Security Findings
            # =========================

            st.subheader(
                "🚨 Security Findings"
            )

            if findings:

                for index, item in enumerate(
                    findings,
                    start=1
                ):

                    if not isinstance(item, dict):
                        continue

                    category = (
                        item.get("category")
                        or item.get("type")
                        or "unknown"
                    )

                    severity = item.get(
                        "severity",
                        "unknown"
                    )

                    file_path = item.get(
                        "file",
                        "unknown"
                    )

                    match = (
                        item.get("match")
                        or item.get("pattern")
                        or "detected"
                    )

                    recommendation = get_recommendation(
                        category
                    )

                    with st.expander(
                        f"{index}. {severity.upper()} - {category}"
                    ):

                        st.write(
                            "**File:**",
                            file_path
                        )

                        st.write(
                            "**Category:**",
                            category
                        )

                        st.write(
                            "**Severity:**",
                            severity.upper()
                        )

                        st.write(
                            "**Detected:**",
                            match
                        )

                        st.write(
                            "**Recommendation:**",
                            recommendation
                        )

            else:

                st.success(
                    "No security findings detected."
                )

            st.divider()


            # =========================
            # Security Report
            # =========================

            st.subheader(
                "📄 Security Report"
            )

            st.text_area(
                "Report",
                report,
                height=500
            )


            # =========================
            # Download Reports
            # =========================

            st.subheader(
                "⬇️ Download Reports"
            )

            html_report = build_html_report(
                results,
                report
            )

            json_report = json.dumps(
                results,
                indent=2,
                ensure_ascii=False
            )

            download_col1, download_col2 = st.columns(2)

            with download_col1:

                st.download_button(
                    label="Download HTML Report",
                    data=html_report,
                    file_name="agent_skill_security_report.html",
                    mime="text/html"
                )

            with download_col2:

                st.download_button(
                    label="Download JSON Report",
                    data=json_report,
                    file_name="agent_skill_security_report.json",
                    mime="application/json"
                )


        except Exception as e:

            st.error(
                f"Scanner error: {e}"
            )