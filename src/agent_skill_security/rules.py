import re


PROMPT_INJECTION_PATTERNS = [

    r"ignore\s+previous\s+instructions",

    r"forget\s+(your\s+)?system\s+prompt",

    r"ignore\s+all\s+instructions",

    r"jailbreak",

    r"developer\s+mode",

    r"bypass\s+safety",

    r"reveal\s+system\s+prompt",

]



SECRET_PATTERNS = [

    r"sk-[a-zA-Z0-9]{20,}",

    r"api[_-]?key\s*=",

    r"apikey\s*=",

    r"secret[_-]?key\s*=",

    r"password\s*=",

    r"token\s*=",

]



DANGEROUS_PATTERNS = [

    r"os\.system\s*\(",

    r"subprocess\.(run|call|Popen)",

    r"rm\s+-rf",

    r"eval\s*\(",

    r"exec\s*\(",

]




def scan_prompt(text: str):

    findings = []


    lower_text = text.lower()



    # Prompt Injection

    for pattern in PROMPT_INJECTION_PATTERNS:

        if re.search(pattern, lower_text):

            findings.append({

                "category": "prompt_injection",

                "type": "prompt_injection",

                "match": pattern,

                "severity": "high"

            })

            break




    # Secret Exposure

    for pattern in SECRET_PATTERNS:

        if re.search(pattern, lower_text):

            findings.append({

                "category": "secret_exposure",

                "type": "secret_exposure",

                "match": pattern,

                "severity": "high"

            })

            break





    # Dangerous Shell / Code

    for pattern in DANGEROUS_PATTERNS:

        if re.search(pattern, lower_text):

            findings.append({

                "category": "dangerous_shell",

                "type": "dangerous_shell",

                "match": pattern,

                "severity": "high"

            })

            break



    return findings
