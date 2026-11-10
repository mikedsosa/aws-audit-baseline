"""Command line for local plan assessment. No AWS calls and no apply."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aws_baseline_evidence import __version__
from aws_baseline_evidence.plan import PlanInputError, parse_plan
from aws_baseline_evidence.report import build_document, exit_code_for, result_of, to_json, to_text
from aws_baseline_evidence.rules import evaluate

HARD_MAX_BYTES = 8_000_000
DEFAULT_MAX_BYTES = 2_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aws-baseline-evidence",
        description=(
            "Assess one Terraform plan JSON file against a small private-bucket "
            "and audit-log baseline. This is not a compliance certification."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"aws-baseline-evidence {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    assess = commands.add_parser("assess", help="Read a plan JSON file and write evidence")
    assess.add_argument(
        "plan", type=Path, help="Path to terraform show -json output or a labeled fixture"
    )
    assess.add_argument("--format", choices=("text", "json"), default="text")
    assess.add_argument("--json-out", type=Path, help="Write JSON evidence to this path")
    assess.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args(argv)
    try:
        if args.max_bytes < 1 or args.max_bytes > HARD_MAX_BYTES:
            raise PlanInputError("--max-bytes must be from 1 through 8000000")
        raw = _read_limited(args.plan, args.max_bytes)
        document = assess_bytes(raw)
    except PlanInputError as exc:
        print(f"aws-baseline-evidence: {exc.message}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"aws-baseline-evidence: {exc.filename or 'file'}: {exc.strerror}", file=sys.stderr)
        return 2
    text = to_text(document)
    payload = to_json(document)
    if args.format == "json":
        sys.stdout.write(payload)
    else:
        sys.stdout.write(text)
    if args.json_out is not None:
        if args.json_out.parent != Path(".") and not args.json_out.parent.is_dir():
            print("aws-baseline-evidence: JSON output directory does not exist", file=sys.stderr)
            return 2
        args.json_out.write_text(payload, encoding="utf-8")
    summary = document["summary"]
    assert isinstance(summary, dict)
    return int(summary["exit_code"])


def assess_bytes(raw: bytes) -> dict[str, object]:
    plan = parse_plan(raw)
    findings = evaluate(plan)
    unsupported = [
        {"address": resource.address, "mode": resource.mode, "type": resource.type_name}
        for resource in plan.resources
        if resource.mode != "managed" or resource.type_name not in _supported()
    ]
    unsupported.sort(key=lambda row: row["address"])
    document = build_document(
        findings=findings,
        input_sha256=plan.sha256,
        input_bytes=plan.byte_length,
        format_version=plan.format_version,
        terraform_version=plan.terraform_version,
        evidence_class=plan.evidence_class,
        fixture_label=plan.fixture_label,
        unsupported=unsupported,
    )
    # Keep the exit code in the document aligned with the finding set.
    summary = document["summary"]
    assert isinstance(summary, dict)
    assert summary["exit_code"] == exit_code_for(result_of(findings))
    return document


def _supported() -> frozenset[str]:
    from aws_baseline_evidence.catalog import SUPPORTED_TYPES

    return SUPPORTED_TYPES


def _read_limited(path: Path, max_bytes: int) -> bytes:
    if not path.is_file():
        raise PlanInputError("plan path is not a regular file")
    size = path.stat().st_size
    if size > max_bytes:
        raise PlanInputError(f"plan file is {size} bytes, over the limit of {max_bytes}")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise PlanInputError("plan file is over the byte limit")
    return data
