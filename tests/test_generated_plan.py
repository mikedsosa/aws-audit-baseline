import json
from pathlib import Path

from aws_baseline_evidence.cli import assess_bytes

PLAN = Path("tests/fixtures/generated/offline.plan.json")


def test_generated_offline_plan_is_not_a_deployment() -> None:
    raw = PLAN.read_bytes()
    text = raw.decode("utf-8")
    assert "AKIA" not in text
    assert "ASIA" not in text
    assert "offline-plan-not-a-credential" in text
    document = assess_bytes(raw)
    summary = document["summary"]
    assert document["input"]["evidence_class"] == "terraform_plan_json"
    assert document["input"]["fixture_label"] is None
    assert document["input"]["deployed_aws_verified"] is False
    assert document["input"]["terraform_version"] == "1.17.1"
    assert summary["fail"] == 0
    assert summary["unknown"] > 0
    assert summary["result"] == "unknown"
    assert summary["exit_code"] == 3
    unknown = {item["rule_id"] for item in document["findings"] if item["status"] == "unknown"}
    assert unknown == {"CT-DEST-001", "KMS-ALIAS-001", "KMS-SEP-001", "S3-ENC-001"}
    passed = {item["rule_id"] for item in document["findings"] if item["status"] == "pass"}
    assert "S3-BPA-001" in passed
    assert "CT-FLAG-001" in passed
    assert "CT-DATA-001" in passed
    assert "not a compliance certification" in document["coverage"]["certification"]
    parsed = json.loads(text)
    assert parsed["applyable"] is True
    assert parsed["errored"] is False
