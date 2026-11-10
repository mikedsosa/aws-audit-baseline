"""Parse a Terraform plan JSON file without executing anything inside it."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

MAX_DEPTH = 64
MAX_RESOURCES = 400
MAX_STRING = 200_000
MAX_COLLECTION = 5_000
MAX_KEY = 500

_LABEL = re.compile(r"[a-z0-9-]{1,40}")


class PlanInputError(Exception):
    """The file is not a plan this tool will assess."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Resource:
    address: str
    type_name: str
    name: str
    mode: str
    actions: tuple[str, ...]
    after: dict[str, Any]
    after_unknown: Any

    @property
    def removed(self) -> bool:
        return "delete" in self.actions and "create" not in self.actions


@dataclass(frozen=True)
class ParsedPlan:
    format_version: str
    terraform_version: str | None
    evidence_class: str
    fixture_label: str | None
    resources: tuple[Resource, ...]
    outputs: dict[str, tuple[str, Any]]
    provisioners_known: bool
    provisioner_addresses: tuple[str, ...]
    byte_length: int
    sha256: str


def parse_plan(raw: bytes) -> ParsedPlan:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise PlanInputError("plan JSON must not start with a byte-order mark")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PlanInputError("plan file is not valid UTF-8") from exc
    if _json_depth(text) > MAX_DEPTH:
        raise PlanInputError("plan JSON nesting exceeds the checker limit")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanInputError(f"plan JSON is not valid ({exc.lineno}:{exc.colno})") from exc
    _walk_limits(document)
    if not isinstance(document, dict):
        raise PlanInputError("plan JSON must be an object")
    _reject_state_or_other(document)
    evidence_class, fixture_label = _fixture_label(document)
    changes = document.get("resource_changes")
    if not isinstance(changes, list):
        raise PlanInputError("plan JSON is missing a resource_changes array")
    if len(changes) > MAX_RESOURCES:
        raise PlanInputError("plan JSON has too many resource_changes entries")
    resources = tuple(_resource(entry) for entry in changes)
    addresses = [item.address for item in resources]
    if len(addresses) != len(set(addresses)):
        raise PlanInputError("plan JSON repeats a resource address")
    provisioners_known, provisioner_addresses = _provisioners(document.get("configuration"))
    return ParsedPlan(
        format_version=_format_version(document),
        terraform_version=_optional_string(document.get("terraform_version")),
        evidence_class=evidence_class,
        fixture_label=fixture_label,
        resources=resources,
        outputs=_outputs(document.get("output_changes")),
        provisioners_known=provisioners_known,
        provisioner_addresses=provisioner_addresses,
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _format_version(document: dict[str, Any]) -> str:
    value = document.get("format_version")
    if not isinstance(value, str) or not value.startswith("1."):
        raise PlanInputError("plan format_version must be a 1.x string")
    return value


def _fixture_label(document: dict[str, Any]) -> tuple[str, str | None]:
    marker = document.get("_aws_baseline_fixture")
    if marker is None:
        return "terraform_plan_json", None
    if not isinstance(marker, dict):
        raise PlanInputError("fixture metadata must be an object")
    if marker.get("kind") != "synthetic":
        raise PlanInputError("fixture metadata kind must be synthetic")
    if marker.get("not_deployed_aws") is not True:
        raise PlanInputError("synthetic fixture metadata must set not_deployed_aws true")
    label = marker.get("label")
    if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
        raise PlanInputError("fixture label must be a short lowercase token")
    return "synthetic_fixture", label


def _reject_state_or_other(document: dict[str, Any]) -> None:
    if "values" in document and "resource_changes" not in document:
        raise PlanInputError("this file looks like a state snapshot, not a plan")


def _resource(entry: Any) -> Resource:
    if not isinstance(entry, dict):
        raise PlanInputError("a resource_changes entry is not an object")
    address = entry.get("address")
    type_name = entry.get("type")
    name = entry.get("name")
    mode = entry.get("mode")
    if not all(isinstance(item, str) for item in (address, type_name, name, mode)):
        raise PlanInputError("a resource_changes entry is missing address, mode, type, or name")
    if len(address) > 300 or len(type_name) > 200:
        raise PlanInputError("a resource address or type is too long")
    change = entry.get("change")
    if not isinstance(change, dict):
        raise PlanInputError(f"{address} is missing a change object")
    actions = change.get("actions")
    if (
        not isinstance(actions, list)
        or not actions
        or not all(isinstance(item, str) for item in actions)
    ):
        raise PlanInputError(f"{address} has no actions array")
    after = change.get("after")
    if after is None:
        after = {}
    if not isinstance(after, dict):
        raise PlanInputError(f"{address} change.after is not an object")
    unknown = change.get("after_unknown", {})
    if unknown is False or unknown is None:
        unknown = {}
    if unknown is not True and not isinstance(unknown, dict):
        raise PlanInputError(f"{address} after_unknown is not an object or true")
    return Resource(
        address=address,
        type_name=type_name,
        name=name,
        mode=mode,
        actions=tuple(actions),
        after=after,
        after_unknown=unknown,
    )


def _outputs(raw: Any) -> dict[str, tuple[str, Any]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PlanInputError("output_changes must be an object when present")
    found: dict[str, tuple[str, Any]] = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise PlanInputError("output_changes has an invalid entry")
        change = entry.get("change") if isinstance(entry.get("change"), dict) else entry
        if not isinstance(change, dict) or "after" not in change and "after_unknown" not in change:
            raise PlanInputError(f"output {name} is missing a change object")
        unknown = change.get("after_unknown", {})
        if unknown is True:
            found[name] = ("unknown", None)
            continue
        if unknown not in (False, None, {}):
            found[name] = ("unknown", None)
            continue
        if "after" not in change:
            found[name] = ("absent", None)
            continue
        found[name] = ("known", change.get("after"))
    return found


def _provisioners(configuration: Any) -> tuple[bool, tuple[str, ...]]:
    if configuration is None:
        return False, ()
    if not isinstance(configuration, dict):
        raise PlanInputError("configuration must be an object when present")
    root = configuration.get("root_module")
    if not isinstance(root, dict):
        raise PlanInputError("configuration.root_module must be an object")
    found: list[str] = []
    seen = 0

    def walk(module: dict[str, Any]) -> None:
        nonlocal seen
        seen += 1
        if seen > 50:
            raise PlanInputError("configuration has too many modules")
        resources = module.get("resources") or []
        if not isinstance(resources, list):
            raise PlanInputError("configuration resources must be an array")
        for resource in resources:
            if not isinstance(resource, dict):
                raise PlanInputError("a configuration resource is not an object")
            provisioners = resource.get("provisioners")
            if provisioners:
                found.append(str(resource.get("address", "unknown")))
        calls = module.get("module_calls") or {}
        if not isinstance(calls, dict):
            raise PlanInputError("module_calls must be an object")
        for call in calls.values():
            if isinstance(call, dict) and isinstance(call.get("module"), dict):
                walk(call["module"])

    walk(root)
    return True, tuple(sorted(found))


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and len(value) <= 80:
        return value
    return None


def _json_depth(text: str) -> int:
    depth = 0
    maximum = 0
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "{[":
            depth += 1
            maximum = max(maximum, depth)
        elif char in "}]":
            depth = max(0, depth - 1)
    return maximum


def _walk_limits(node: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise PlanInputError("plan JSON nesting exceeds the checker limit")
    if isinstance(node, dict):
        if len(node) > MAX_COLLECTION:
            raise PlanInputError("plan JSON object has too many keys")
        for key, value in node.items():
            if not isinstance(key, str) or len(key) > MAX_KEY:
                raise PlanInputError("plan JSON has an invalid object key")
            _walk_limits(value, depth + 1)
        return
    if isinstance(node, list):
        if len(node) > MAX_COLLECTION:
            raise PlanInputError("plan JSON array is too large")
        for item in node:
            _walk_limits(item, depth + 1)
        return
    if isinstance(node, str):
        if len(node) > MAX_STRING:
            raise PlanInputError("plan JSON contains a string longer than the checker limit")
        return
    if isinstance(node, (int, float)) or node is None or isinstance(node, bool):
        return
    raise PlanInputError("plan JSON contains an unsupported value type")
