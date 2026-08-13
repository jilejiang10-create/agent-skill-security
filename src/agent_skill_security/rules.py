PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "forget your system prompt",
    "jailbreak",
    "developer mode",
    "bypass safety"
]


SECRET_PATTERNS = [
    "sk-",
    "api_key",
    "apikey",
    "password",
    "token"
]


DANGEROUS_PATTERNS = [
    "os.system",
    "subprocess",
    "rm -rf",
    "eval("
]


def scan_prompt(text: str):
    findings = []

    lower_text = text.lower()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in lower_text:
            if not any(f["type"] == "prompt_injection" for f in findings):
                findings.append({
                    "type": "prompt_injection",
                    "match": pattern,
                    "severity": "high"
                })

    for pattern in SECRET_PATTERNS:
        if pattern in lower_text:
            if not any(f["type"] == "secret_exposure" for f in findings):
                findings.append({
                    "type": "secret_exposure",
                    "match": pattern,
                    "severity": "high"
                })

    for pattern in DANGEROUS_PATTERNS:
        if pattern in lower_text:
            if not any(f["type"] == "dangerous_code" for f in findings):
                findings.append({
                    "type": "dangerous_code",
                    "match": pattern,
                    "severity": "medium"
                })

    return findings
