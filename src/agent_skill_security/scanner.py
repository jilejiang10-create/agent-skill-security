from pathlib import Path
import re
from .rules import scan_prompt
from .risk import calculate_risk
DANGEROUS_PATTERNS = {
    "hardcoded_api_key": [
        r"sk-[A-Za-z0-9_-]{20,}",
        r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]",
        r"secret[_-]?key\s*=\s*['\"][^'\"]+['\"]",
    ],
    "dangerous_shell": [
        r"rm\s+-rf",
        r"curl\s+.*\|\s*(bash|sh)",
        r"wget\s+.*\|\s*(bash|sh)",
        r"os\.system\(",
        r"subprocess\.(run|Popen|call)\(",
    ],
    "network_request": [
        r"requests\.(get|post|put|delete|patch)\(",
        r"urllib\.request",
        r"httpx\.(get|post|put|delete|patch)\(",
    ],
    "file_system_write": [
        r"open\([^)]*,\s*['\"](w|a|x)",
        r"shutil\.rmtree\(",
        r"os\.remove\(",
        r"os\.unlink\(",
    ],
    "prompt_injection": [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+the\s+system\s+prompt",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"bypass\s+(the\s+)?instructions",
    ],
}


def scan_text(text: str):
    findings = []

    findings.extend(scan_prompt(text))
    
    for category, patterns in DANGEROUS_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                findings.append(
                    {
                        "category": category,
                        "match": match.group(0),
                    }
                )

    return findings


def scan_file(file_path: Path):
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [
            {
                "category": "read_error",
                "match": str(exc),
            }
        ]

    return scan_text(text)


def scan_directory(directory: str):
    root = Path(directory)
    results = {}

    allowed_extensions = {
        ".py",
        ".js",
        ".ts",
        ".json",
        ".yaml",
        ".yml",
        ".md",
        ".txt",
        ".sh",
    }

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in allowed_extensions:
            continue

        findings = scan_file(file_path)

        if findings:
            results[str(file_path)] = {
                "findings": findings,
                "risk": calculate_risk(findings)
            }

    return results


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."

    print(f"Scanning: {target}")

    results = scan_directory(target)

    if not results:
        print("No suspicious patterns found.")
    else:
        print("\nPotential security findings:\n")

        for file_name, findings in results.items():
            print(f"[FILE] {file_name}")

            for finding in findings:
                print(
                    f"  - {finding['category']}: "
                    f"{finding['match']}"
                )

            print()
