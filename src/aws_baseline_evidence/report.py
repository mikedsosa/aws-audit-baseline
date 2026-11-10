"""Deterministic text and JSON evidence. No timestamps."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from aws_baseline_evidence import __version__
from aws_baseline_evidence.catalog import (
    CERTIFICATION_SENTENCE,
    EVIDENCE_SCHEMA_VERSION,
    NOT_ASSESSED,
    RULESET_ID,
    RULESET_VERSION,
)

_HASH_FILES = ("catalog.py", "lookup.py", "plan.py", "policy.py", "rules.py")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    status: str
    resource_addresses: tuple[str, ...]
    reason: str


def ruleset_files_sha256() -> str:
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent
    for name in _HASH_FILES:
        data = (root / name).read_bytes()
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def result_of(findings: list[Finding]) -> str:
    statuses = {item.status for item in findings}
    if "fail" in statuses:
        return "fail"
    if "unknown" in statuses:
        return "unknown"
    return "pass"


def exit_code_for(result: str) -> int:
    return {"pass": 0, "fail": 1, "unknown": 3}[result]


def build_document(
    *,
    findings: list[Finding],
    input_sha256: str,
    input_bytes: int,
    format_version: str,
    terraform_version: str | None,
    evidence_class: str,
    fixture_label: str | None,
    unsupported: list[dict[str, str]],
) -> dict[str, object]:
    ordered = sorted(
        findings, key=lambda item: (item.rule_id, item.resource_addresses, item.reason)
    )
    counts = {
        status: sum(item.status == status for item in ordered)
        for status in ("pass", "fail", "unknown")
    }
    result = result_of(ordered)
    document: dict[str, object] = {
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": {"name": "aws-baseline-evidence", "version": __version__},
        "ruleset": {
            "id": RULESET_ID,
            "version": RULESET_VERSION,
            "files_sha256": ruleset_files_sha256(),
        },
        "input": {
            "sha256": input_sha256,
            "byte_length": input_bytes,
            "format_version": format_version,
            "terraform_version": terraform_version,
            "evidence_class": evidence_class,
            "fixture_label": fixture_label,
            "deployed_aws_verified": False,
        },
        "coverage": {
            "assessed_rule_ids": [item.rule_id for item in ordered],
            "not_assessed": [{"id": item_id, "detail": detail} for item_id, detail in NOT_ASSESSED],
            "certification": "none. " + CERTIFICATION_SENTENCE,
        },
        "summary": {
            "pass": counts["pass"],
            "fail": counts["fail"],
            "unknown": counts["unknown"],
            "result": result,
            "exit_code": exit_code_for(result),
        },
        "findings": [
            {
                "rule_id": item.rule_id,
                "status": item.status,
                "resource_addresses": list(item.resource_addresses),
                "reason": item.reason,
            }
            for item in ordered
        ],
        "unsupported_resources": unsupported,
        "evidence_content_sha256_scope": (
            "sha256 of canonical JSON with sorted keys and compact separators, "
            "excluding the evidence_content_sha256 field"
        ),
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    document["evidence_content_sha256"] = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    return document


def to_json(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def to_text(document: dict[str, object]) -> str:
    tool = document["tool"]
    ruleset = document["ruleset"]
    incoming = document["input"]
    summary = document["summary"]
    assert isinstance(tool, dict)
    assert isinstance(ruleset, dict)
    assert isinstance(incoming, dict)
    assert isinstance(summary, dict)
    lines = [
        f"aws-baseline-evidence {tool['version']}",
        f"ruleset {ruleset['id']} {ruleset['version']}",
        f"evidence_schema {document['evidence_schema_version']}",
        f"evidence_class {incoming['evidence_class']}",
        f"fixture_label {incoming['fixture_label']}",
        "deployed_aws_verified false",
        f"input_sha256 {incoming['sha256']}",
        f"input_bytes {incoming['byte_length']}",
        f"ruleset_files_sha256 {ruleset['files_sha256']}",
        f"evidence_content_sha256 {document['evidence_content_sha256']}",
        CERTIFICATION_SENTENCE,
        "This file is not evidence of a deployed AWS account.",
        "Missing and unknown attributes are not counted as passes.",
        "",
    ]
    findings = document["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        addresses = ",".join(finding["resource_addresses"]) or "-"
        lines.append(f"[{finding['status']}] {finding['rule_id']} {addresses} {finding['reason']}")
    lines.extend(
        [
            "",
            (
                f"summary pass={summary['pass']} fail={summary['fail']} "
                f"unknown={summary['unknown']} result={summary['result']}"
            ),
            f"exit_code {summary['exit_code']}",
        ]
    )
    return "\n".join(lines) + "\n"
