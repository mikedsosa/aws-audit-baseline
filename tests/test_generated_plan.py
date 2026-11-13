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
    for rule_id in ("S3-ACCT-BPA-001", "S3-RET-001", "KMS-SCOPE-001", "IAM-TAMPER-001"):
        assert rule_id in passed
    assert summary["pass"] == 47
    assert "not a compliance certification" in document["coverage"]["certification"]
    parsed = json.loads(text)
    assert parsed["applyable"] is True
    assert parsed["errored"] is False


def test_generated_plan_has_review_gap_fixes() -> None:
    parsed = json.loads(PLAN.read_text(encoding="utf-8"))
    after = {item["address"]: item["change"]["after"] for item in parsed["resource_changes"]}
    block = after["aws_s3_account_public_access_block.account"]
    assert block["account_id"] == "123456789012"
    assert all(
        block[name] is True
        for name in (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        )
    )
    selector = after["aws_cloudtrail.audit_logs"]["event_selector"][0]
    assert selector["data_resource"] == [
        {"type": "AWS::S3::Object", "values": ["arn:aws:s3:::studybase-123456789012-data/"]}
    ]
    rules = after["aws_s3_bucket_lifecycle_configuration.audit_logs"]["rule"]
    noncurrent = [
        item["noncurrent_days"] for rule in rules for item in rule["noncurrent_version_expiration"]
    ]
    assert noncurrent == [365]
    assert after["aws_s3_bucket.audit_logs"]["object_lock_enabled"] is False
    assert not any(key.startswith("aws_s3_bucket_object_lock_configuration") for key in after)
