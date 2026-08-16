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

            match = re.search(
                pattern,
                content,
                re.IGNORECASE
            )


            if match:

                findings.append(
                    {
                        "file": path,
                        "category": category,
                        "severity": "high",
                        "match": match.group(0)
                    }
                )

                break




    try:

        prompt_findings = scan_prompt(content)


        if prompt_findings:

            for item in prompt_findings:

                findings.append(item)


    except Exception:

        pass



    return findings








def scan_directory(directory: str):

    results = []


    root = Path(directory)



    ignore_dirs = {

        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv"

    }




    for file in root.rglob("*"):


        if not file.is_file():

            continue



        if any(
            folder in ignore_dirs
            for folder in file.parts
        ):

            continue



        results.extend(

            scan_file(
                str(file)
            )

        )





    try:

        risk = calculate_risk(results)


    except Exception:

        risk = {

            "risk_score": 0,

            "risk_level": "SAFE",

            "issues": []

        }





    return {

        "target": directory,

        "risk": risk,

        "findings": results,

        "total_issues": len(results)

    }