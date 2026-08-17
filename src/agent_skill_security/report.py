"""Plain-text reporting for canonical scanner results."""

from datetime import datetime
from typing import Dict, Iterable, List, Mapping, Tuple

from agent_skill_security.risk import risk_level_for_score
from agent_skill_security.rules import safe_display_text, safe_secret_evidence


RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SECRET_CATEGORIES = {"hardcoded_api_key", "secret_exposure", "secret"}


def get_risk_summary(result: Mapping[str, object]) -> Tuple[int, str]:
    """Return the score and level already present in a canonical ScanResult."""

    risk = result.get("risk", {})
    if isinstance(risk, Mapping):
        raw_score = risk.get("risk_score", 0)
        raw_level = risk.get("risk_level")
    else:
        # Compatibility for the earliest report API, which accepted risk: 80.
        raw_score = risk
        raw_level = None

    try:
        score = max(0, min(int(raw_score), 100))
    except (TypeError, ValueError):
        score = 0

    level = (
        raw_level
        if isinstance(raw_level, str) and raw_level in RISK_LEVELS
        else risk_level_for_score(score)
    )
    return score, level


def _iter_results(results: object) -> Iterable[Dict[str, object]]:
    if isinstance(results, Mapping):
        if "findings" in results or "target" in results or "schema_version" in results:
            yield dict(results)
            return

        # Compatibility for {"file.py": {"findings": ..., "risk": ...}}.
        for name, value in results.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("target", str(name))
                item.setdefault("files_scanned", 1)
                yield item
        return

    if isinstance(results, (list, tuple)):
        for value in results:
            if isinstance(value, Mapping):
                yield dict(value)


def _safe_evidence(finding: Mapping[str, object]) -> str:
    category = str(finding.get("category") or finding.get("type") or "unknown")
    risk_group = str(finding.get("risk_group") or "")
    evidence = str(finding.get("match", "detected"))

    if risk_group == "secrets" or category in SECRET_CATEGORIES:
        return safe_secret_evidence(evidence)
    return safe_display_text(evidence)


def generate_report(results: object) -> str:
    """Generate a report without recalculating canonical risk data."""

    normalized = list(_iter_results(results))
    total_files = 0
    total_files_seen = 0
    total_findings = 0
    total_skipped_files = 0
    total_scan_errors = 0
    max_score = 0
    max_level = "LOW"
    report_findings: List[Tuple[Dict[str, object], Mapping[str, object]]] = []
    total_truncated_files = 0
    scan_complete = True

    for data in normalized:
        files_scanned = data.get("files_scanned", 1)
        if isinstance(files_scanned, int) and not isinstance(files_scanned, bool):
            total_files += max(files_scanned, 0)
        else:
            total_files += 1

        files_seen = data.get("files_seen", files_scanned)
        if isinstance(files_seen, int) and not isinstance(files_seen, bool):
            total_files_seen += max(files_seen, 0)
        else:
            total_files_seen += 1

        skipped_files = data.get("skipped_files", [])
        if isinstance(skipped_files, (list, tuple)):
            total_skipped_files += len(skipped_files)
        scan_errors = data.get("scan_errors", [])
        if isinstance(scan_errors, (list, tuple)):
            total_scan_errors += len(scan_errors)
        if data.get("scan_complete") is False:
            scan_complete = False

        score, level = get_risk_summary(data)
        if score >= max_score:
            max_score = score
            max_level = level

        findings = data.get("findings", [])
        if isinstance(findings, (list, tuple)):
            for finding in findings:
                if isinstance(finding, Mapping):
                    report_findings.append((data, finding))
                    total_findings += 1
        truncated_files = data.get("truncated_files", [])
        if isinstance(truncated_files, (list, tuple)):
            total_truncated_files += len(truncated_files)

    if not scan_complete:
        status = (
            "SCAN INCOMPLETE - SECURITY ISSUES FOUND"
            if total_findings
            else "SCAN INCOMPLETE"
        )
    else:
        status = (
            "SECURITY ISSUES FOUND" if total_findings else "NO SECURITY ISSUES FOUND"
        )
    lines = [
        "=" * 50,
        "Agent Skill Security Report",
        "=" * 50,
        "Generated: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "",
        "Status: {}".format(status),
        "",
        "Findings",
        "-" * 50,
    ]

    if not report_findings:
        lines.append("None")

    for data, finding in report_findings:
        file_name = safe_display_text(
            finding.get("file") or data.get("target") or data.get("file") or "unknown"
        )
        line = finding.get("line")
        column = finding.get("column")
        location = file_name
        if isinstance(line, int):
            location += ":{}".format(line)
            if isinstance(column, int):
                location += ":{}".format(column)

        severity = safe_display_text(finding.get("severity", "unknown"))
        category = safe_display_text(
            finding.get("category") or finding.get("type") or "unknown"
        )
        rule_id = safe_display_text(finding.get("rule_id", "unknown"))
        lines.append(
            "- [{}] {}: {} (rule: {}) -- {}".format(
                severity, location, category, rule_id, _safe_evidence(finding)
            )
        )

    lines.extend(
        [
            "",
            "-" * 50,
            "Scan Complete: {}".format("YES" if scan_complete else "NO"),
            "Files Seen: {}".format(total_files_seen),
            "Files Scanned: {}".format(total_files),
            "Skipped Files: {}".format(total_skipped_files),
            "Scan Errors: {}".format(total_scan_errors),
            "Total Findings: {}".format(total_findings),
            "Truncated Files: {}".format(total_truncated_files),
            "Overall Risk Score: {}/100".format(max_score),
            "Overall Risk Level: {}".format(max_level),
        ]
    )
    return "\n".join(lines)
