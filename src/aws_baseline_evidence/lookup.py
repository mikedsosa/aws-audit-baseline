"""Read planned values without treating a missing or unknown attribute as a pass."""

from __future__ import annotations

from typing import Any

from aws_baseline_evidence.plan import Resource


def lookup(after: Any, after_unknown: Any, path: tuple[Any, ...]) -> tuple[str, Any]:
    """Return known, unknown, or absent for a path inside one resource."""
    node = after
    unknown = after_unknown
    for part in path:
        if unknown is True:
            return "unknown", None
        if isinstance(node, dict) and isinstance(part, str):
            unknown_map = unknown if isinstance(unknown, dict) else None
            if part not in node:
                if unknown_map is not None and part in unknown_map:
                    return "unknown", None
                return "absent", None
            node = node[part]
            unknown = None if unknown_map is None else unknown_map.get(part)
            continue
        if isinstance(node, list) and isinstance(part, int):
            if part < 0 or part >= len(node):
                if isinstance(unknown, list) and 0 <= part < len(unknown):
                    return "unknown", None
                return "absent", None
            node = node[part]
            unknown = unknown[part] if isinstance(unknown, list) and part < len(unknown) else None
            continue
        return "absent", None
    if unknown is True:
        return "unknown", None
    return "known", node


def attr(resource: Resource, path: tuple[Any, ...]) -> tuple[str, Any]:
    return lookup(resource.after, resource.after_unknown, path)


def string_set(value: Any) -> set[str] | None:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def shown(value: object, limit: int = 80) -> str:
    text = repr(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text
