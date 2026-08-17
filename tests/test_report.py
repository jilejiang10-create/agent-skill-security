from agent_skill_security.report import generate_report


def test_generate_report():
    results = {
        "test.py": {
            "findings": [
                {
                    "category": "secret",
                    "match": "API_KEY"
                }
            ],
            "risk": 80
        }
    }

    report = generate_report(results)

    assert isinstance(report, str)
    assert "Status: SECURITY ISSUES FOUND" in report
    assert "[unknown] test.py: secret (rule: unknown) -- [REDACTED]" in report
    assert "API_KEY" not in report
    assert "Scan Complete: YES" in report
    assert "Files Seen: 1" in report
    assert "Files Scanned: 1" in report
    assert "Total Findings: 1" in report
    assert "Overall Risk Score: 80/100" in report
    assert "Overall Risk Level: CRITICAL" in report


def test_generate_report_uses_canonical_scan_result_without_recalculation():
    result = {
        "schema_version": "1.0",
        "target": "src",
        "scan_complete": True,
        "files_seen": 2,
        "files_scanned": 2,
        "skipped_files": [],
        "truncated_files": [],
        "scan_errors": [],
        "findings": [
            {
                "rule_id": "network.requests",
                "rule_ids": ["network.requests"],
                "file": "client.py",
                "category": "network_request",
                "type": "network_request",
                "risk_group": "network_request",
                "severity": "medium",
                "match": "requests.get(",
                "redacted": False,
                "line": 3,
                "column": 5,
            }
        ],
        "total_issues": 1,
        "risk": {
            "risk_score": 15,
            "risk_level": "MEDIUM",
            "issues": ["network_request"],
            "risk_groups": ["network_request"],
            "total_findings": 1,
        },
    }

    report = generate_report(result)

    assert "Status: SECURITY ISSUES FOUND" in report
    assert (
        "[medium] client.py:3:5: network_request "
        "(rule: network.requests) -- requests.get(" in report
    )
    assert "Files Seen: 2" in report
    assert "Files Scanned: 2" in report
    assert "Total Findings: 1" in report
    assert "Overall Risk Score: 15/100" in report
    assert "Overall Risk Level: MEDIUM" in report
