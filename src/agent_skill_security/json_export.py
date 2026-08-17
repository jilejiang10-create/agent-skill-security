"""JSON export with defense-in-depth secret redaction."""

import json
from typing import Mapping

from agent_skill_security.rules import safe_display_text, safe_secret_evidence


SECRET_CATEGORIES = {"hardcoded_api_key", "secret_exposure", "secret"}


def _sanitize(value: object) -> object:
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item in value.items():
            safe_key = safe_display_text(key) if isinstance(key, str) else key
            if safe_key in sanitized:
                suffix = 2
                candidate = "{}#{}".format(safe_key, suffix)
                while candidate in sanitized:
                    suffix += 1
                    candidate = "{}#{}".format(safe_key, suffix)
                safe_key = candidate
            sanitized[safe_key] = _sanitize(item)
        category = sanitized.get("category") or sanitized.get("type")
        risk_group = sanitized.get("risk_group")
        if (risk_group == "secrets" or category in SECRET_CATEGORIES) and "match" in sanitized:
            sanitized["match"] = safe_secret_evidence(sanitized["match"])
            sanitized["redacted"] = True
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return safe_display_text(value)
    return value


def generate_json_report(results: object) -> str:
    return json.dumps(_sanitize(results), indent=4, ensure_ascii=False)
