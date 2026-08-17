"""Streamlit dashboard confined to an administrator-selected scan root."""

import os
from pathlib import Path

import streamlit as st

from agent_skill_security.export import generate_html_report
from agent_skill_security.json_export import generate_json_report
from agent_skill_security.report import generate_report, get_risk_summary
from agent_skill_security.rules import safe_display_text
from agent_skill_security.scanner import ScanPathError, scan_directory


SCAN_ROOT = Path(
    os.environ.get("AGENT_SKILL_SECURITY_SCAN_ROOT", str(Path.cwd()))
).expanduser().resolve()


def _positive_environment_integer(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


MAX_FILE_SIZE = _positive_environment_integer(
    "AGENT_SKILL_SECURITY_MAX_FILE_SIZE", 5 * 1024 * 1024
)
MAX_FILES = _positive_environment_integer("AGENT_SKILL_SECURITY_MAX_FILES", 10000)
MAX_FINDINGS_PER_FILE = _positive_environment_integer(
    "AGENT_SKILL_SECURITY_MAX_FINDINGS_PER_FILE", 5000
)


st.set_page_config(
    page_title="Agent Skill Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Agent Skill Security")
st.write("AI Agent / Plugin / Automation Script Security Scanner")
st.caption("Allowed scan root: {}".format(safe_display_text(SCAN_ROOT)))
st.caption(
    "Web limits: {} files, {} bytes and {} findings per file".format(
        MAX_FILES, MAX_FILE_SIZE, MAX_FINDINGS_PER_FILE
    )
)
st.divider()

target = st.text_input(
    "Target project path (relative to the allowed scan root)",
    ".",
)

if st.button("Start Security Scan"):
    with st.spinner("Scanning..."):
        try:
            results = scan_directory(
                target,
                allowed_root=SCAN_ROOT,
                max_file_size=MAX_FILE_SIZE,
                max_files=MAX_FILES,
                max_findings_per_file=MAX_FINDINGS_PER_FILE,
            )
            report = generate_report(results)
            html_report = generate_html_report(report)
            json_report = generate_json_report(results)
            score, level = get_risk_summary(results)

            if results["scan_complete"]:
                st.success("Scan completed")
            else:
                st.warning(
                    "Scan completed with incomplete coverage; review skipped, "
                    "truncated, and error counts in the report."
                )
            st.subheader("Security Report")
            st.text_area("Report", report, height=450)

            st.download_button(
                label="Download HTML Report",
                data=html_report,
                file_name="security_report.html",
                mime="text/html",
            )
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name="security_report.json",
                mime="application/json",
            )

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Risk Score", "{}/100".format(score))
            with col2:
                if level in {"CRITICAL", "HIGH"}:
                    st.error("Risk Level: {}".format(level))
                elif level == "MEDIUM":
                    st.warning("Risk Level: {}".format(level))
                else:
                    st.success("Risk Level: {}".format(level))

        except ScanPathError as exc:
            st.error("Scan path rejected: {}".format(exc))
        except Exception as exc:
            st.error("Scanner error: {}".format(exc))
