"""Canonical risk scoring for scanner findings."""

from typing import Dict, Mapping, Sequence

from agent_skill_security.rules import RULES


CATEGORY_ALIASES = {
    "secret": "secret_exposure",
    "dangerous_command": "dangerous_shell",
    "filesystem_write": "file_system_write",
    "network_access": "network_request",
}

CATEGORY_TO_GROUP = {rule.category: rule.risk_group for rule in RULES}

# Weights are assigned to risk groups, not individual rule aliases. This means
# two representations of the same underlying secret exposure cannot add 70.
RISK_GROUP_WEIGHTS = {
    "secrets": 35,
    "dangerous_shell": 30,
    "network_request": 15,
    "file_system_write": 15,
    "prompt_injection": 25,
}

# Backwards-compatible exported mapping for callers of the original API.
RISK_WEIGHTS = dict(RISK_GROUP_WEIGHTS)
RISK_WEIGHTS.update(
    {
        "secret_exposure": 35,
        "hardcoded_api_key": 35,
    }
)


def risk_level_for_score(score: int) -> str:
    """Map a score to the public thresholds documented in README.md."""

    bounded_score = max(0, min(int(score), 100))
    if bounded_score >= 80:
        return "CRITICAL"
    if bounded_score >= 40:
        return "HIGH"
    if bounded_score >= 15:
        return "MEDIUM"
    return "LOW"


def calculate_risk(findings: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    """Calculate one deterministic risk result from normalized findings."""

    score = 0
    issues = []
    risk_groups = []
    seen_categories = set()
    seen_groups = set()

    for item in findings:
        raw_category = item.get("category") or item.get("type")
        if not raw_category:
            continue

        category = CATEGORY_ALIASES.get(str(raw_category), str(raw_category))
        finding_group = item.get("risk_group")
        group = (
            finding_group
            if isinstance(finding_group, str)
            and finding_group in RISK_GROUP_WEIGHTS
            else CATEGORY_TO_GROUP.get(category)
        )
        if group is None:
            continue

        if category not in seen_categories:
            seen_categories.add(category)
            issues.append(category)

        if group not in seen_groups:
            seen_groups.add(group)
            risk_groups.append(group)
            score += RISK_GROUP_WEIGHTS[group]

    score = min(score, 100)
    return {
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        "issues": issues,
        "risk_groups": risk_groups,
        "total_findings": len(findings),
    }
