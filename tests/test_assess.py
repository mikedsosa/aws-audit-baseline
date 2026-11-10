import json
from pathlib import Path

import pytest

from aws_baseline_evidence.catalog import NOT_ASSESSED, RULES
from aws_baseline_evidence.cli import assess_bytes
from aws_baseline_evidence.plan import PlanInputError, parse_plan
from aws_baseline_evidence.report import to_json, to_text
from tests.fixture_factory import (
    absent_force_destroy_document,
    compliant_document,
    dumps,
    missing_public_access_document,
    noncompliant_document,
    unknown_document,
    with_provisioner,
)


def _statuses(document: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for finding in document["findings"]:
        found.setdefault(finding["rule_id"], set()).add(finding["status"])
    return found


def _assess(document: dict) -> dict:
    return assess_bytes(dumps(document))


def test_compliant_fixture_passes_every_rule() -> None:
    document = _assess(compliant_document())
    statuses = _statuses(document)
    assert set(statuses) == {rule_id for rule_id, _summary in RULES}
    failing = {rule_id: findings for rule_id, findings in statuses.items() if findings != {"pass"}}
    assert failing == {}
    assert document["summary"]["result"] == "pass"
    assert document["summary"]["exit_code"] == 0
    assert document["summary"]["unknown"] == 0
    assert document["input"]["evidence_class"] == "synthetic_fixture"
    assert document["input"]["fixture_label"] == "compliant"
    assert document["input"]["deployed_aws_verified"] is False
    assert "not a compliance certification" in document["coverage"]["certification"]
    text = to_text(document)
    assert "not evidence of a deployed AWS account" in text
    assert "synthetic_fixture" in text


def test_unknown_attributes_are_not_passes() -> None:
    document = _assess(unknown_document())
    statuses = _statuses(document)
    assert "fail" not in {status for values in statuses.values() for status in values}
    assert document["summary"]["fail"] == 0
    assert document["summary"]["unknown"] > 0
    assert document["summary"]["result"] == "unknown"
    assert document["summary"]["exit_code"] == 3
    assert "unknown" in statuses["S3-BPA-001"]
    assert "pass" not in statuses["S3-BPA-001"] or "unknown" in statuses["S3-BPA-001"]
    bpa = [item for item in document["findings"] if item["rule_id"] == "S3-BPA-001"]
    workload = [item for item in bpa if "workload_data" in ",".join(item["resource_addresses"])]
    assert workload and workload[0]["status"] == "unknown"
    assert document["summary"]["pass"] != len(document["findings"])


def test_noncompliant_fixture_fails_closed() -> None:
    document = _assess(noncompliant_document())
    statuses = _statuses(document)
    assert document["summary"]["result"] == "fail"
    assert document["summary"]["exit_code"] == 1
    assert "fail" in statuses["S3-BPA-001"]
    assert "fail" in statuses["S3-ENC-001"]
    assert "fail" in statuses["S3-VER-001"]
    assert "fail" in statuses["S3-OWN-001"]
    assert "fail" in statuses["S3-TLS-001"]
    assert "fail" in statuses["S3-DESTROY-001"]
    assert "fail" in statuses["S3-LOCK-001"]
    assert "fail" in statuses["KMS-ROT-001"]
    assert "fail" in statuses["KMS-WIN-001"]
    assert "fail" in statuses["CT-FLAG-001"]
    assert "fail" in statuses["CT-DEST-001"]
    assert "fail" in statuses["CT-DATA-001"]
    assert "fail" in statuses["IAM-TRUST-001"]
    assert "fail" in statuses["IAM-PERM-001"]
    assert "fail" in statuses["DISCLAIM-001"]
    assert "unknown" in statuses["UNSUPPORTED-TYPE-001"]
    assert document["unsupported_resources"][0]["type"] == "aws_instance"
    assert document["input"]["deployed_aws_verified"] is False


def test_missing_public_access_block_fails() -> None:
    document = _assess(missing_public_access_document())
    bpa = [item for item in document["findings"] if item["rule_id"] == "S3-BPA-001"]
    assert {item["status"] for item in bpa} == {"fail"}
    assert document["summary"]["exit_code"] == 1
    assert "pass" in _statuses(document)["S3-VER-001"]


def test_absent_force_destroy_is_not_a_pass() -> None:
    document = _assess(absent_force_destroy_document())
    destroy = [item for item in document["findings"] if item["rule_id"] == "S3-DESTROY-001"]
    assert {item["status"] for item in destroy} == {"fail"}
    assert all("absent" in item["reason"] for item in destroy)
    assert document["summary"]["exit_code"] == 1


def test_same_bytes_are_deterministic() -> None:
    raw = dumps(compliant_document())
    first = to_json(assess_bytes(raw))
    second = to_json(assess_bytes(raw))
    assert first == second
    assert "evidence_content_sha256" in json.loads(first)


def test_provisioner_is_not_executed(tmp_path) -> None:
    marker = tmp_path / "should-not-exist"
    document = _assess(
        with_provisioner(f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')")
    )
    assert not marker.exists()
    statuses = _statuses(document)
    assert statuses["PROV-001"] == {"fail"}
    assert document["summary"]["exit_code"] == 1


def test_malformed_json_is_an_input_error() -> None:
    with pytest.raises(PlanInputError):
        parse_plan(b"{")


def test_non_object_json_is_an_input_error() -> None:
    with pytest.raises(PlanInputError):
        parse_plan(b"[]")


def test_state_snapshot_is_rejected() -> None:
    with pytest.raises(PlanInputError):
        parse_plan(b'{"version": 4, "values": {"root_module": {}}}')


def test_deep_json_is_rejected() -> None:
    payload = '{"a":' * 70 + "1" + "}" * 70
    with pytest.raises(PlanInputError):
        parse_plan(payload.encode())


def test_too_many_resources_is_rejected() -> None:
    changes = []
    for index in range(401):
        changes.append(
            {
                "address": f"aws_s3_bucket.b{index}",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": f"b{index}",
                "change": {"actions": ["create"], "after": {}, "after_unknown": {}},
            }
        )
    raw = json.dumps(
        {
            "format_version": "1.2",
            "resource_changes": changes,
            "configuration": {"root_module": {"resources": []}},
        }
    ).encode()
    with pytest.raises(PlanInputError):
        parse_plan(raw)


def test_fixture_cannot_claim_a_live_kind() -> None:
    document = compliant_document()
    document["_aws_baseline_fixture"]["kind"] = "deployed"
    with pytest.raises(PlanInputError):
        parse_plan(dumps(document))


def test_rules_doc_names_every_catalog_id() -> None:
    text = Path("docs/RULES.md").read_text(encoding="utf-8")
    for rule_id, _summary in RULES:
        assert rule_id in text
    for item_id, _detail in NOT_ASSESSED:
        assert item_id in text


def test_committed_synthetic_fixtures_match_the_factory() -> None:
    from tests.fixture_factory import (
        absent_force_destroy_document,
        compliant_document,
        missing_public_access_document,
        noncompliant_document,
        unknown_document,
    )

    expected = {
        "synthetic-compliant.json": compliant_document(),
        "synthetic-noncompliant.json": noncompliant_document(),
        "synthetic-unknown.json": unknown_document(),
        "synthetic-missing-public-access.json": missing_public_access_document(),
        "synthetic-absent-force-destroy.json": absent_force_destroy_document(),
    }
    root = Path("tests/fixtures")
    for name, document in expected.items():
        assert json.loads((root / name).read_text(encoding="utf-8")) == document


def test_code_looking_strings_are_data() -> None:
    document = compliant_document()
    _after = None
    for resource in document["resource_changes"]:
        if resource["address"] == "aws_s3_bucket.workload_data":
            resource["change"]["after"]["tags"]["Note"] = "__import__('os').system('echo pwned')"
            _after = resource
    assert _after is not None
    assessed = _assess(document)
    assert assessed["summary"]["result"] == "pass"
