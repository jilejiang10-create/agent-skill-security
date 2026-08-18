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
        r"httpx\.(get|post|put|delete|patch)\(",
        r"urllib",
    ],

    "file_system_write": [
        r"open\(.*,\s*['\"]w",
        r"shutil\.rmtree\(",
        r"os\.remove\(",
        r"os\.unlink\(",
    ],

}


IGNORE_FILES = {
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
}


IGNORE_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
}



def scan_file(path):

    findings = []

    file_path = Path(path)

    try:

        content = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception:

        return findings


    for category, patterns in DANGEROUS_PATTERNS.items():

        for pattern in patterns:

            match = re.search(
                pattern,
                content,
                re.IGNORECASE
            )

            if match:

                findings.append(
                    {
                        "file": str(path),
                        "category": category,
                        "severity": "high",
                        "match": match.group(0)
                    }
                )

                break



    try:

        prompt_findings = scan_prompt(content)

        for item in prompt_findings:

            item["file"] = str(path)

            findings.append(item)


    except Exception:

        pass


    return findings




def scan_directory(directory):

    findings = []

    files_scanned = 0


    root = Path(directory)


    if not root.exists():

        return {
            "target": str(root),
            "files_scanned": 0,
            "findings": [],
            "risk": {
                "risk_score":0,
                "risk_level":"LOW"
            },
            "total_issues":0
        }



    for file in root.rglob("*"):


        if not file.is_file():

            continue


        if file.name in IGNORE_FILES:

            continue


        if any(
            d in file.parts
            for d in IGNORE_DIRS
        ):

            continue



        files_scanned += 1


        findings.extend(
            scan_file(file)
        )



    risk = calculate_risk(
        findings
    )


    return {

        "target": str(root),

        "files_scanned": files_scanned,

        "findings": findings,

        "risk": risk,

        "total_issues": len(findings)

    }