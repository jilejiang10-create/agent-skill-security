PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "forget your system prompt",
    "jailbreak",
    "developer mode",
    "bypass safety"
]


def scan_prompt(text: str):
    findings = []

    lower_text = text.lower()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in lower_text:
            findings.append({
                "type": "prompt_injection",
                "match": pattern,
                "severity": "high"
            })

    return findings
