"""Parse IAM, bucket, and key policy JSON embedded in a plan.

The parser uses json.loads only. It does not evaluate strings as code.
"""

from __future__ import annotations

import json
from typing import Any

MAX_POLICY_CHARS = 100_000
MAX_STATEMENTS = 40


def parse_policy(value: Any) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(value, str):
        return "unknown", None
    if len(value) > MAX_POLICY_CHARS:
        return "unknown", None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return "unknown", None
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError:
            return "unknown", None
    if not isinstance(parsed, dict):
        return "unknown", None
    return "known", parsed


def statements(policy: dict[str, Any]) -> tuple[str, list[dict[str, Any]] | None]:
    raw = policy.get("Statement")
    if isinstance(raw, dict):
        items = [raw]
    elif isinstance(raw, list) and all(isinstance(item, dict) for item in raw):
        items = raw
    else:
        return "unknown", None
    if len(items) > MAX_STATEMENTS:
        return "unknown", None
    if any(key in item for item in items for key in ("NotPrincipal", "NotAction", "NotResource")):
        return "unknown", None
    return "known", items


def as_strings(value: Any) -> set[str] | None:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def principals_aws(principal: Any) -> tuple[str, set[str]]:
    """Return known AWS principal ids, or unknown/absent."""
    if principal == "*":
        return "known", {"*"}
    if isinstance(principal, str):
        return "known", {principal}
    if not isinstance(principal, dict):
        return "unknown", set()
    if "AWS" not in principal:
        return "absent", set()
    found = as_strings(principal.get("AWS"))
    if found is None:
        return "unknown", set()
    return "known", found


def principal_services(principal: Any) -> tuple[str, set[str]]:
    if not isinstance(principal, dict) or "Service" not in principal:
        return "absent", set()
    found = as_strings(principal.get("Service"))
    if found is None:
        return "unknown", set()
    return "known", found


def condition_values(statement: dict[str, Any], operator: str, key: str) -> tuple[str, set[str]]:
    """Read one named condition operator. A different operator on the same key is unknown."""
    condition = statement.get("Condition")
    if condition is None:
        return "absent", set()
    if not isinstance(condition, dict):
        return "unknown", set()
    if operator not in condition:
        # A different operator on the same key is not evaluated.
        for name, block in condition.items():
            if name != operator and isinstance(block, dict) and key in block:
                return "unknown", set()
        return "absent", set()
    block = condition[operator]
    if not isinstance(block, dict) or key not in block:
        return "absent", set()
    found = as_strings(block[key])
    if found is None:
        raw = block[key]
        if isinstance(raw, bool):
            return "known", {"true" if raw else "false"}
        return "unknown", set()
    return "known", {item.lower() if item in {"True", "False"} else item for item in found}


def bool_condition(statement: dict[str, Any], key: str) -> tuple[str, set[str]]:
    state, values = condition_values(statement, "Bool", key)
    if state != "known":
        return state, values
    return "known", {item.lower() for item in values}


def resources_of(statement: dict[str, Any]) -> tuple[str, set[str]]:
    if "Resource" not in statement:
        return "absent", set()
    found = as_strings(statement.get("Resource"))
    if found is None:
        return "unknown", set()
    return "known", found


def actions_of(statement: dict[str, Any]) -> tuple[str, set[str]]:
    if "Action" not in statement:
        return "absent", set()
    found = as_strings(statement.get("Action"))
    if found is None:
        return "unknown", set()
    return "known", found
