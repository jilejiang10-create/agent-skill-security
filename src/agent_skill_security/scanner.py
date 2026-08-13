from pathlib import Path
import re

from agent_skill_security.rules import scan_prompt
from agent_skill_security.risk import calculate_risk

DANGEROUS_PATTERNS = {
    "hardcoded_api_key": [
        r"sk-[A-Za-z0-9]{20,}",
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
        r"url.*request",
        r"httpx\.(get|post|put|delete|patch)\(",
    ],

    "file_system_write": [
        r"open\(.*,\s*['\"]w",
        r"shutil\.rmtree\(",
        r"os\.remove\(",
        r"os\.unlink\(",
    ],

    "prompt_injection": [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+the\s+system\s+prompt",
        r"reveal\s+the\s+system\s+prompt",
        r"bypass\s+the\s+instructions",
    ],
}


def scan_file(path: str):
    findings = []

    try:
        content = Path(path).read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except Exception:
        return findings


    for category, patterns in DANGEROUS_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, content, re.IGNORECASE):

                if re.search(pattern, content, re.IGNORECASE):
                    if not any(
                        f["category"] == category
                        for f in findings
                    ):
                        findings.append(
                            {
                                "file": path,
                                "category": category,
                                "severity": "high"
                            }
                        )
        
                    break


    prompt_result = scan_prompt(content)
    
    if prompt_result:
        for item in prompt_result:
            if not any(
                f["type"] == item["type"]
                for f in findings
            ):
                findings.append(item)


    return findings



def scan_directory(directory: str):

    results = []

    root = Path(directory)


    for file in root.rglob("*"):

        if file.is_file():

            results.extend(
                scan_file(str(file))
            )


    risk = calculate_risk(results)

    return {
        "file": directory,
        "risk": risk,
        "findings": results
    }
