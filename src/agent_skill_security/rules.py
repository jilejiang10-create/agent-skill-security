"""Security rule registry and finding generation.

This module is the single source of truth for detection rules. Findings are
created here so sensitive evidence is redacted before it can reach a report,
JSON export, log, or user interface.
"""

from bisect import bisect_right
from dataclasses import dataclass
from heapq import heappop, heappush
import re
from typing import Dict, List, Match, Optional, Pattern, Tuple
from unicodedata import category as unicode_category


REDACTED = "[REDACTED]"
_SAFE_REDACTED_EVIDENCE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_-]*\s*=\s*)?\[REDACTED\]$"
)


@dataclass(frozen=True)
class Rule:
    """A compiled security detection rule."""

    rule_id: str
    category: str
    risk_group: str
    severity: str
    pattern: Pattern[str]
    sensitive: bool = False
    priority: int = 100
    evidence: Optional[str] = None


def _rule(
    rule_id: str,
    category: str,
    risk_group: str,
    pattern: str,
    *,
    sensitive: bool = False,
    priority: int = 100,
    evidence: Optional[str] = None,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        category=category,
        risk_group=risk_group,
        severity="high",
        pattern=re.compile(pattern, re.IGNORECASE),
        sensitive=sensitive,
        priority=priority,
        evidence=evidence,
    )


# Keep this registry ordered and use stable rule IDs. It intentionally covers
# the union of every pattern that previously lived in rules.py and scanner.py.
RULES: Tuple[Rule, ...] = (
    _rule(
        "secret.api_key_assignment",
        "hardcoded_api_key",
        "secrets",
        r"(?P<name>(?:[A-Za-z_][A-Za-z0-9_-]*[_-])?(?:api[_-]?key|apikey))"
        r"\b[ \t]*=(?![ \t]*\[REDACTED\])[ \t]*"
        r"(?:(?P<quote>['\"])[^'\"\r\n]*(?P=quote)|[^\s#;,}\]]+)?",
        sensitive=True,
        priority=10,
    ),
    _rule(
        "secret.credential_assignment",
        "secret_exposure",
        "secrets",
        r"(?P<name>(?:[A-Za-z_][A-Za-z0-9_-]*[_-])?"
        r"(?:secret[_-]?key|password|token))"
        r"\b[ \t]*=(?![ \t]*\[REDACTED\])[ \t]*"
        r"(?:(?P<quote>['\"])[^'\"\r\n]*(?P=quote)|[^\s#;,}\]]+)?",
        sensitive=True,
        priority=10,
    ),
    _rule(
        "secret.openai_style_key",
        "hardcoded_api_key",
        "secrets",
        r"sk-[A-Za-z0-9]{20,}",
        sensitive=True,
        priority=20,
    ),
    _rule(
        "prompt.ignore_previous_instructions",
        "prompt_injection",
        "prompt_injection",
        r"ignore\s+(?:all\s+)?previous\s+instructions",
    ),
    _rule(
        "prompt.ignore_all_instructions",
        "prompt_injection",
        "prompt_injection",
        r"ignore\s+all\s+instructions",
    ),
    _rule(
        "prompt.forget_system_prompt",
        "prompt_injection",
        "prompt_injection",
        r"forget\s+(?:your\s+)?system\s+prompt",
    ),
    _rule(
        "prompt.ignore_system_prompt",
        "prompt_injection",
        "prompt_injection",
        r"ignore\s+the\s+system\s+prompt",
    ),
    _rule(
        "prompt.reveal_system_prompt",
        "prompt_injection",
        "prompt_injection",
        r"reveal\s+(?:the\s+)?system\s+prompt",
    ),
    _rule(
        "prompt.bypass_instructions",
        "prompt_injection",
        "prompt_injection",
        r"bypass\s+the\s+instructions",
    ),
    _rule(
        "prompt.bypass_safety",
        "prompt_injection",
        "prompt_injection",
        r"bypass\s+safety",
    ),
    _rule(
        "prompt.jailbreak",
        "prompt_injection",
        "prompt_injection",
        r"jailbreak",
    ),
    _rule(
        "prompt.developer_mode",
        "prompt_injection",
        "prompt_injection",
        r"developer\s+mode",
    ),
    _rule(
        "shell.remove_recursive",
        "dangerous_shell",
        "dangerous_shell",
        r"rm\s+-rf",
    ),
    _rule(
        "shell.pipe_download_to_shell",
        "dangerous_shell",
        "dangerous_shell",
        r"(?:curl|wget)\s+[^\r\n]*\|\s*(?:bash|sh)\b",
        evidence="download command piped to shell",
    ),
    _rule(
        "shell.os_system",
        "dangerous_shell",
        "dangerous_shell",
        r"os\.system\s*\(",
    ),
    _rule(
        "shell.subprocess",
        "dangerous_shell",
        "dangerous_shell",
        r"subprocess\.(?:run|call|Popen)",
    ),
    _rule(
        "code.eval",
        "dangerous_shell",
        "dangerous_shell",
        r"eval\s*\(",
    ),
    _rule(
        "code.exec",
        "dangerous_shell",
        "dangerous_shell",
        r"exec\s*\(",
    ),
    _rule(
        "network.requests",
        "network_request",
        "network_request",
        r"requests\.(?:get|post|put|delete|patch)\s*\(",
    ),
    _rule(
        "network.httpx",
        "network_request",
        "network_request",
        r"httpx\.(?:get|post|put|delete|patch)\s*\(",
    ),
    _rule(
        "network.urllib",
        "network_request",
        "network_request",
        r"urllib",
    ),
    _rule(
        "filesystem.open_write",
        "file_system_write",
        "file_system_write",
        r"open\s*\([^\r\n]*,\s*['\"][^'\"]*w",
        evidence="open(..., write mode)",
    ),
    _rule(
        "filesystem.rmtree",
        "file_system_write",
        "file_system_write",
        r"shutil\.rmtree\s*\(",
    ),
    _rule(
        "filesystem.remove",
        "file_system_write",
        "file_system_write",
        r"os\.remove\s*\(",
    ),
    _rule(
        "filesystem.unlink",
        "file_system_write",
        "file_system_write",
        r"os\.unlink\s*\(",
    ),
)


# Backwards-compatible pattern collections. They are derived from RULES and
# are not executed separately, preventing the former double-scan behaviour.
PROMPT_INJECTION_PATTERNS = [
    rule.pattern.pattern for rule in RULES if rule.category == "prompt_injection"
]
SECRET_PATTERNS = [
    rule.pattern.pattern for rule in RULES if rule.risk_group == "secrets"
]
DANGEROUS_PATTERNS = [
    rule.pattern.pattern for rule in RULES if rule.category == "dangerous_shell"
]
RULE_PATTERNS = {
    category: [rule.pattern.pattern for rule in RULES if rule.category == category]
    for category in dict.fromkeys(rule.category for rule in RULES)
}

_DANGEROUS_EXECUTION_WRAPPERS = {"shell.os_system", "shell.subprocess"}
_DANGEROUS_COMMAND_PAYLOADS = {
    "shell.remove_recursive",
    "shell.pipe_download_to_shell",
}


def _line_starts(text: str) -> List[int]:
    return [0] + [index + 1 for index, character in enumerate(text) if character == "\n"]


def _position(line_starts: List[int], offset: int) -> Tuple[int, int]:
    line_index = bisect_right(line_starts, offset) - 1
    return line_index + 1, offset - line_starts[line_index] + 1


def _redacted_evidence(rule: Rule, match: Match[str]) -> str:
    """Return useful evidence without ever returning credential contents."""

    # Every rule in the secrets risk group is forced through this function,
    # even if a future contributor forgets to set sensitive=True.
    name = match.groupdict().get("name")
    if name:
        return "{} = {}".format(name, REDACTED)
    return REDACTED


def safe_secret_evidence(value: object) -> str:
    """Accept only the scanner's strict redaction format for secret evidence."""

    evidence = str(value)
    return evidence if _SAFE_REDACTED_EVIDENCE.fullmatch(evidence) else REDACTED


def redact_secret_substrings(value: object) -> str:
    """Redact recognized credentials in any externally visible string."""

    redacted = str(value)
    if _SAFE_REDACTED_EVIDENCE.fullmatch(redacted):
        return redacted
    for rule in RULES:
        if rule.risk_group != "secrets":
            continue
        redacted = rule.pattern.sub(
            lambda match, current_rule=rule: _redacted_evidence(current_rule, match),
            redacted,
        )
    return redacted


def safe_display_text(value: object) -> str:
    """Redact secrets and neutralize terminal control characters."""

    redacted = redact_secret_substrings(value)
    return "".join(_escaped_control(character) for character in redacted)


def safe_multiline_text(value: object) -> str:
    """Sanitize report text while preserving ordinary line formatting."""

    redacted = redact_secret_substrings(value)
    return "".join(
        character if character in "\r\n\t" else _escaped_control(character)
        for character in redacted
    )


def _escaped_control(character: str) -> str:
    if unicode_category(character) not in {"Cc", "Cf", "Zl", "Zp"}:
        return character
    codepoint = ord(character)
    if codepoint <= 0xFF:
        return "\\x{:02x}".format(codepoint)
    if codepoint <= 0xFFFF:
        return "\\u{:04x}".format(codepoint)
    return "\\U{:08x}".format(codepoint)


def _call_end(text: str, opening_end: int) -> int:
    """Find a same-line call boundary for duplicate-operation grouping."""

    depth = 1
    quote = None
    escaped = False
    for index in range(opening_end, len(text)):
        character = text[index]
        if character in "\r\n":
            return index
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def _merge_rule_ids(target: Dict[str, object], source: Dict[str, object]) -> None:
    combined = list(target["rule_ids"])
    for rule_id in source["rule_ids"]:
        if rule_id not in combined:
            combined.append(rule_id)
    target["rule_ids"] = combined


def _taint_secret_overlaps(candidates: List[Dict[str, object]]) -> None:
    intervals = sorted(
        (int(item["_start"]), int(item["_end"]))
        for item in candidates
        if item["risk_group"] == "secrets"
    )
    if not intervals:
        return

    merged: List[List[int]] = []
    for start, end in intervals:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    starts = [interval[0] for interval in merged]

    for candidate in candidates:
        if candidate["risk_group"] == "secrets":
            continue
        start = int(candidate["_start"])
        end = int(candidate["_end"])
        index = bisect_right(starts, end - 1) - 1
        if index >= 0 and merged[index][1] > start:
            candidate["match"] = REDACTED
            candidate["redacted"] = True


def _deduplicate_candidates(
    candidates: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    deduplicated: List[Dict[str, object]] = []
    exact_spans: Dict[Tuple[object, object, object], Dict[str, object]] = {}
    last_secret = None

    for candidate in candidates:
        exact_key = (
            candidate["category"],
            candidate["_start"],
            candidate["_end"],
        )
        exact = exact_spans.get(exact_key)
        if exact is not None:
            _merge_rule_ids(exact, candidate)
            continue

        if candidate["risk_group"] == "secrets":
            if (
                last_secret is not None
                and int(candidate["_start"]) < int(last_secret["_secret_cluster_end"])
            ):
                _merge_rule_ids(last_secret, candidate)
                last_secret["_secret_cluster_end"] = max(
                    int(last_secret["_secret_cluster_end"]), int(candidate["_end"])
                )
                continue
            candidate["_secret_cluster_end"] = candidate["_end"]
            last_secret = candidate

        deduplicated.append(candidate)
        exact_spans[exact_key] = candidate

    return deduplicated


def _merge_dangerous_operations(candidates: List[Dict[str, object]]) -> None:
    wrappers = sorted(
        (
            candidate
            for candidate in candidates
            if candidate["rule_id"] in _DANGEROUS_EXECUTION_WRAPPERS
        ),
        key=lambda item: int(item["_start"]),
    )
    if not wrappers:
        return

    wrapper_starts = []
    prefix_largest_wrapper = []
    largest = None
    for wrapper in wrappers:
        wrapper_starts.append(int(wrapper["_start"]))
        if largest is None or int(wrapper["_operation_end"]) > int(
            largest["_operation_end"]
        ):
            largest = wrapper
        prefix_largest_wrapper.append(largest)

    for payload in candidates:
        if payload["rule_id"] not in _DANGEROUS_COMMAND_PAYLOADS:
            continue
        index = bisect_right(wrapper_starts, int(payload["_start"])) - 1
        if index < 0:
            continue
        wrapper = prefix_largest_wrapper[index]
        if int(payload["_end"]) <= int(wrapper["_operation_end"]):
            _merge_rule_ids(wrapper, payload)
            payload["_removed"] = True


def _candidate(
    text: str,
    safe_source: str,
    line_starts: List[int],
    rule: Rule,
    match: Match[str],
) -> Dict[str, object]:
    line, column = _position(line_starts, match.start())
    operation_end = match.end()
    if rule.rule_id in _DANGEROUS_EXECUTION_WRAPPERS:
        opening = text.find("(", match.start(), match.end())
        if opening < 0:
            line_end = len(text)
            for separator in ("\r", "\n"):
                position = text.find(separator, match.end())
                if position >= 0:
                    line_end = min(line_end, position)
            possible_opening = text.find("(", match.end(), line_end)
            if possible_opening >= 0 and not text[
                match.end() : possible_opening
            ].strip():
                opening = possible_opening
        if opening >= 0:
            operation_end = _call_end(text, opening + 1)

    return {
        "_start": match.start(),
        "_end": match.end(),
        "_priority": rule.priority,
        "_operation_end": operation_end,
        "rule_id": rule.rule_id,
        "rule_ids": [rule.rule_id],
        "file": safe_source,
        "category": rule.category,
        "type": rule.category,
        "risk_group": rule.risk_group,
        "severity": rule.severity,
        "match": (
            _redacted_evidence(rule, match)
            if rule.risk_group == "secrets" or rule.sensitive
            else safe_display_text(rule.evidence or match.group(0))
        ),
        "redacted": rule.risk_group == "secrets" or rule.sensitive,
        "line": line,
        "column": column,
    }


def scan_text_with_metadata(
    text: str,
    *,
    source: str = "<memory>",
    max_findings: Optional[int] = None,
) -> Tuple[List[Dict[str, object]], bool]:
    """Scan text and report whether Web-facing match collection was truncated."""

    if max_findings is not None and (
        not isinstance(max_findings, int)
        or isinstance(max_findings, bool)
        or max_findings < 1
    ):
        raise ValueError("max_findings must be a positive integer or None")

    candidates: List[Dict[str, object]] = []
    line_starts = _line_starts(text)
    safe_source = safe_display_text(source)
    pending = []

    for rule_index, rule in enumerate(RULES):
        iterator = iter(rule.pattern.finditer(text))
        first = next(iterator, None)
        if first is not None:
            # Always retain the first hit from every rule so a flood of early,
            # low-value matches cannot hide a later secret or command finding.
            candidates.append(_candidate(text, safe_source, line_starts, rule, first))
            following = next(iterator, None)
            if following is not None:
                heappush(
                    pending,
                    (following.start(), rule_index, following, iterator, rule),
                )

    while pending and (max_findings is None or len(candidates) < max_findings):
        _, rule_index, match, iterator, rule = heappop(pending)
        candidates.append(_candidate(text, safe_source, line_starts, rule, match))
        following = next(iterator, None)
        if following is not None:
            heappush(
                pending,
                (following.start(), rule_index, following, iterator, rule),
            )

    truncated = bool(pending)

    candidates.sort(
        key=lambda item: (
            int(item["_start"]),
            int(item["_priority"]),
            int(item["_end"]),
            str(item["rule_id"]),
        )
    )
    _taint_secret_overlaps(candidates)
    deduplicated = _deduplicate_candidates(candidates)
    _merge_dangerous_operations(deduplicated)

    findings: List[Dict[str, object]] = []
    for candidate in deduplicated:
        if candidate.get("_removed"):
            continue
        findings.append(
            {
                key: value
                for key, value in candidate.items()
                if not key.startswith("_")
            }
        )

    findings.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]),
            int(item["column"]),
            str(item["rule_id"]),
        )
    )
    return findings, truncated


def scan_text(
    text: str,
    *,
    source: str = "<memory>",
    max_findings: Optional[int] = None,
) -> List[Dict[str, object]]:
    """Scan text once and return deterministic, normalized findings."""

    findings, _ = scan_text_with_metadata(
        text, source=source, max_findings=max_findings
    )
    return findings


def scan_prompt(text: str) -> List[Dict[str, object]]:
    """Backwards-compatible wrapper for callers of the original API."""

    return scan_text(text, source="<prompt>")
