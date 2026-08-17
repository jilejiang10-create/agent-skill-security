from html import unescape
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys

import pytest
from streamlit.testing.v1 import AppTest

from agent_skill_security import __version__
from agent_skill_security.cli import main as cli_main
from agent_skill_security.export import generate_html_report
from agent_skill_security.json_export import generate_json_report
from agent_skill_security.report import generate_report
from agent_skill_security.scanner import scan_directory


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_FILE = PROJECT_ROOT / "src" / "agent_skill_security" / "app.py"


def _assert_contract(result):
    assert result["schema_version"] == "1.0"
    assert isinstance(result["target"], str)
    assert isinstance(result["scan_complete"], bool)
    assert isinstance(result["files_scanned"], int)
    assert result["files_scanned"] >= 0
    assert isinstance(result["files_seen"], int)
    assert isinstance(result["skipped_files"], list)
    assert isinstance(result["truncated_files"], list)
    assert isinstance(result["scan_errors"], list)
    assert result["total_issues"] == len(result["findings"])
    assert result["total_issues"] == result["risk"]["total_findings"]
    assert set(result["risk"]) == {
        "risk_score",
        "risk_level",
        "issues",
        "risk_groups",
        "total_findings",
    }
    assert result["risk"]["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    for finding in result["findings"]:
        assert set(finding) >= {
            "rule_id",
            "rule_ids",
            "file",
            "category",
            "type",
            "risk_group",
            "severity",
            "match",
            "redacted",
            "line",
            "column",
        }
        assert finding["type"] == finding["category"]
        assert isinstance(finding["line"], int) and finding["line"] >= 1
        assert isinstance(finding["column"], int) and finding["column"] >= 1


def _write_critical_fixture(root):
    (root / "risk.py").write_text(
        'api_key="sk-AbCdEf0123456789GhIjKlMn"\n'
        'os.system("id")\n'
        'requests.get("https://example.test")',
        encoding="utf-8",
    )
    (root / "clean.md").write_text("hello", encoding="utf-8")


def test_empty_scan_and_all_serializers_agree(tmp_path):
    result = scan_directory(str(tmp_path), allowed_root=str(tmp_path))
    _assert_contract(result)

    assert result["files_scanned"] == 0
    assert result["scan_complete"] is True
    assert result["total_issues"] == 0
    assert result["risk"] == {
        "risk_score": 0,
        "risk_level": "LOW",
        "issues": [],
        "risk_groups": [],
        "total_findings": 0,
    }

    text_report = generate_report(result)
    assert "Status: NO SECURITY ISSUES FOUND" in text_report
    assert "Status: SECURITY ISSUES FOUND" not in text_report
    assert "Files Scanned: 0" in text_report
    assert "Scan Complete: YES" in text_report
    assert "Total Findings: 0" in text_report
    assert "Overall Risk Score: 0/100" in text_report
    assert "Overall Risk Level: LOW" in text_report
    assert json.loads(generate_json_report(result)) == result
    assert text_report in unescape(generate_html_report(text_report))


def test_counts_and_risk_match_cli_json_and_html(tmp_path, monkeypatch, capsys):
    _write_critical_fixture(tmp_path)
    result = scan_directory(str(tmp_path), allowed_root=str(tmp_path))
    _assert_contract(result)

    assert result["files_scanned"] == 2
    assert result["total_issues"] == 3
    assert (result["risk"]["risk_score"], result["risk"]["risk_level"]) == (
        80,
        "CRITICAL",
    )

    text_report = generate_report(result)
    json_report = generate_json_report(result)
    html_report = generate_html_report(text_report)
    assert "Files Scanned: 2" in text_report
    assert "Total Findings: 3" in text_report
    assert "Overall Risk Score: 80/100" in text_report
    assert "Overall Risk Level: CRITICAL" in text_report
    assert json.loads(json_report)["risk"] == result["risk"]
    assert text_report in unescape(html_report)

    monkeypatch.setattr(sys, "argv", ["agent-security", str(tmp_path)])
    cli_main()
    cli_output = capsys.readouterr().out
    assert "Files Scanned: 2" in cli_output
    assert "Total Findings: 3" in cli_output
    assert "Overall Risk Score: 80/100" in cli_output
    assert "Overall Risk Level: CRITICAL" in cli_output


def test_streamlit_uses_same_risk_and_enforces_scan_root(tmp_path, monkeypatch):
    _write_critical_fixture(tmp_path)
    sibling = tmp_path.parent / "outside-web-root"
    sibling.mkdir(exist_ok=True)
    (sibling / "outside.py").write_text('os.system("id")', encoding="utf-8")
    monkeypatch.setenv("AGENT_SKILL_SECURITY_SCAN_ROOT", str(tmp_path))

    app = AppTest.from_file(str(APP_FILE), default_timeout=10)
    app.run()
    assert not app.exception

    app.button[0].click().run()
    assert not app.exception
    assert app.metric[0].value == "80/100"
    assert any(element.value == "Risk Level: CRITICAL" for element in app.error)
    assert "Overall Risk Score: 80/100" in app.text_area[0].value
    assert "Overall Risk Level: CRITICAL" in app.text_area[0].value
    assert "sk-AbCdEf0123456789GhIjKlMn" not in app.text_area[0].value

    app.text_input[0].set_value(str(sibling)).run()
    app.button[0].click().run()
    assert any("Scan path rejected" in element.value for element in app.error)
    assert len(app.metric) == 0


def test_streamlit_applies_resource_limits(tmp_path, monkeypatch):
    (tmp_path / "small.py").write_text('os.system("id")', encoding="utf-8")
    (tmp_path / "large.py").write_text(
        "x" * 256 + '\nsubprocess.run(["id"])', encoding="utf-8"
    )
    monkeypatch.setenv("AGENT_SKILL_SECURITY_SCAN_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENT_SKILL_SECURITY_MAX_FILE_SIZE", "64")
    monkeypatch.setenv("AGENT_SKILL_SECURITY_MAX_FILES", "10")

    app = AppTest.from_file(str(APP_FILE), default_timeout=10)
    app.run()
    app.button[0].click().run()

    assert not app.exception
    assert app.metric[0].value == "30/100"
    assert "Files Scanned: 1" in app.text_area[0].value
    assert "Total Findings: 1" in app.text_area[0].value
    assert "Scan Complete: NO" in app.text_area[0].value


def test_streamlit_reports_finding_truncation(tmp_path, monkeypatch):
    (tmp_path / "dense.txt").write_text("jailbreak\n" * 20, encoding="utf-8")
    monkeypatch.setenv("AGENT_SKILL_SECURITY_SCAN_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENT_SKILL_SECURITY_MAX_FINDINGS_PER_FILE", "3")

    app = AppTest.from_file(str(APP_FILE), default_timeout=10)
    app.run()
    app.button[0].click().run()

    assert not app.exception
    assert app.metric[0].value == "25/100"
    assert "Total Findings: 3" in app.text_area[0].value
    assert "Truncated Files: 1" in app.text_area[0].value
    assert "Scan Complete: NO" in app.text_area[0].value


def test_incomplete_scan_is_never_reported_as_clean(tmp_path):
    (tmp_path / "large.txt").write_text("clean" * 100, encoding="utf-8")
    result = scan_directory(str(tmp_path), max_file_size=1)
    report = generate_report(result)

    assert result["scan_complete"] is False
    assert result["risk"]["risk_score"] == 0
    assert result["risk"]["risk_level"] == "LOW"
    assert "Status: SCAN INCOMPLETE" in report
    assert "Status: NO SECURITY ISSUES FOUND" not in report
    assert "Scan Complete: NO" in report
    assert "Files Seen: 1" in report
    assert "Files Scanned: 0" in report
    assert "Skipped Files: 1" in report


def test_package_and_cli_versions_match_pyproject(monkeypatch, capsys):
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__ == "1.0.1"

    monkeypatch.setattr(sys, "argv", ["agent-security", "--version"])
    with pytest.raises(SystemExit) as exc_info:
        cli_main()
    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_reviewed_project_self_scan_is_clean():
    completed = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "self_scan.py")],
        cwd=str(PROJECT_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Status: NO SECURITY ISSUES FOUND" in completed.stdout
    assert "Reviewed rule-definition matches suppressed: 4" in completed.stdout
    assert "line-sha256=" in completed.stdout


def test_self_scan_fails_closed_when_coverage_is_incomplete():
    namespace = runpy.run_path(str(PROJECT_ROOT / "scripts" / "self_scan.py"))
    assert namespace["_should_fail"](
        {
            "total_issues": 0,
            "scan_errors": [],
            "scan_complete": False,
        },
        [],
    )
