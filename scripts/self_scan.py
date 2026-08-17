"""Run the scanner against its own source with an exact reviewed baseline."""

from hashlib import sha256
from pathlib import Path
import sys

from agent_skill_security.report import generate_report
from agent_skill_security.risk import calculate_risk
from agent_skill_security.scanner import scan_directory


EXPECTED_RULE_DEFINITION_MATCHES = {
    (
        "agent_skill_security/rules.py",
        "prompt.jailbreak",
        133,
        17,
        "007148df863c4c1dd7fc4f26807925c2d018e5c776eb43d65fcf78477807f1ef",
    ),
    (
        "agent_skill_security/rules.py",
        "prompt.jailbreak",
        136,
        11,
        "a4d269d2549197bcfcc0f8a3f0629048feccf9b4dd65d0aba12de8fe8c17ac64",
    ),
    (
        "agent_skill_security/rules.py",
        "network.urllib",
        194,
        18,
        "3a672c5f31e5e4f41e4df339297eec71227b4e2b3295a5f5541af24180e3ab99",
    ),
    (
        "agent_skill_security/rules.py",
        "network.urllib",
        197,
        11,
        "65e434700bbe7a428aeeea66c2e920e3e235e957230226998bcb543d2dbbcbac",
    ),
}


def _fingerprint(finding, source_root: Path):
    path = source_root / finding["file"]
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(finding["line"])
    line = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
    return (
        finding["file"],
        finding["rule_id"],
        line_number,
        int(finding["column"]),
        sha256(line.encode("utf-8")).hexdigest(),
    )


def build_self_scan_result(source_root: Path):
    raw_result = scan_directory(str(source_root))
    remaining = set(EXPECTED_RULE_DEFINITION_MATCHES)
    unexpected = []
    suppressed = []

    for finding in raw_result["findings"]:
        fingerprint = _fingerprint(finding, source_root)
        if fingerprint in remaining:
            remaining.remove(fingerprint)
            suppressed.append((finding, fingerprint))
        else:
            unexpected.append(finding)

    missing = sorted(remaining)
    result = dict(raw_result)
    result["findings"] = unexpected
    result["total_issues"] = len(unexpected)
    result["risk"] = calculate_risk(unexpected)
    return result, suppressed, missing


def _should_fail(result, missing) -> bool:
    return bool(
        result["total_issues"]
        or missing
        or result["scan_errors"]
        or not result.get("scan_complete", False)
    )


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    result, suppressed, missing = build_self_scan_result(project_root / "src")
    print(generate_report(result))
    print("Reviewed rule-definition matches suppressed: {}".format(len(suppressed)))
    for finding, fingerprint in suppressed:
        print(
            "  {}:{}:{} {} line-sha256={}".format(
                finding["file"],
                finding["line"],
                finding["column"],
                finding["rule_id"],
                fingerprint[-1],
            )
        )

    if missing:
        print("Self-scan baseline is stale: {}".format(missing))
    if result["scan_errors"]:
        print("Self-scan read errors: {}".format(result["scan_errors"]))

    return 1 if _should_fail(result, missing) else 0


if __name__ == "__main__":
    sys.exit(main())
