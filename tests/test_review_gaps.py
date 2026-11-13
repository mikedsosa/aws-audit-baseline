"""Gap-fix rules from the 2026-11-13 review. Synthetic plans only, no AWS calls."""

import json

import pytest

from aws_baseline_evidence.cli import assess_bytes
from tests.fixture_factory import (
    AUDITOR_ROLE_ARN,
    DATA_BUCKET_ARN,
    LOGS_BUCKET_ARN,
    compliant_document,
    dumps,
    object_lock_document,
)


def _assess(document: dict) -> dict:
    return assess_bytes(dumps(document))


def _statuses(assessed: dict, rule_id: str, address_part: str = "") -> set[str]:
    found = {
        item["status"]
        for item in assessed["findings"]
        if item["rule_id"] == rule_id and address_part in ",".join(item["resource_addresses"])
    }
    assert found, rule_id
    return found


def _resource(document: dict, address: str) -> dict:
    for resource in document["resource_changes"]:
        if resource["address"] == address:
            return resource
    raise KeyError(address)


def _after(document: dict, address: str) -> dict:
    return _resource(document, address)["change"]["after"]


def _policy(document: dict, address: str) -> dict:
    return json.loads(_after(document, address)["policy"])


def _write_policy(document: dict, address: str, policy: dict) -> None:
    _after(document, address)["policy"] = json.dumps(policy)


def _drop(document: dict, type_name: str) -> None:
    document["resource_changes"] = [
        item for item in document["resource_changes"] if item["type"] != type_name
    ]
    resources = document["configuration"]["root_module"]["resources"]
    document["configuration"]["root_module"]["resources"] = [
        item for item in resources if item["type"] != type_name
    ]


NEW_RULES = ("S3-ACCT-BPA-001", "S3-RET-001", "KMS-SCOPE-001", "IAM-TAMPER-001")


def test_compliant_fixture_passes_every_new_rule() -> None:
    assessed = _assess(compliant_document())
    for rule_id in (*NEW_RULES, "CT-DATA-001", "S3-LOCK-001"):
        assert _statuses(assessed, rule_id) == {"pass"}, rule_id
    assert assessed["summary"]["result"] == "pass"


# Account-level Block Public Access


def test_missing_account_public_access_block_fails() -> None:
    document = compliant_document()
    _drop(document, "aws_s3_account_public_access_block")
    assert _statuses(_assess(document), "S3-ACCT-BPA-001") == {"fail"}


@pytest.mark.parametrize(
    "flag",
    ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"],
)
def test_account_public_access_flag_false_fails(flag: str) -> None:
    document = compliant_document()
    _after(document, "aws_s3_account_public_access_block.account")[flag] = False
    assert _statuses(_assess(document), "S3-ACCT-BPA-001") == {"fail"}


def test_account_public_access_other_account_fails() -> None:
    document = compliant_document()
    _after(document, "aws_s3_account_public_access_block.account")["account_id"] = "210987654321"
    assert _statuses(_assess(document), "S3-ACCT-BPA-001") == {"fail"}


def test_account_public_access_unknown_flag_is_unknown() -> None:
    document = compliant_document()
    resource = _resource(document, "aws_s3_account_public_access_block.account")
    resource["change"]["after"].pop("block_public_policy")
    resource["change"]["after_unknown"] = {"block_public_policy": True}
    assert _statuses(_assess(document), "S3-ACCT-BPA-001") == {"unknown"}


def test_two_account_public_access_blocks_fail() -> None:
    document = compliant_document()
    extra = json.loads(
        json.dumps(_resource(document, "aws_s3_account_public_access_block.account"))
    )
    extra["address"] = "aws_s3_account_public_access_block.second"
    extra["name"] = "second"
    document["resource_changes"].append(extra)
    assert _statuses(_assess(document), "S3-ACCT-BPA-001") == {"fail"}


# Audit log retention


def _audit_rules(document: dict) -> list:
    return _after(document, "aws_s3_bucket_lifecycle_configuration.audit_logs")["rule"]


def test_short_noncurrent_retention_fails() -> None:
    document = compliant_document()
    _audit_rules(document)[1]["noncurrent_version_expiration"] = [{"noncurrent_days": 30}]
    assessed = _assess(document)
    assert _statuses(assessed, "S3-RET-001") == {"fail"}
    assert _statuses(assessed, "S3-LIFE-001", "audit_logs") == {"fail"}


def test_extra_prefix_rule_that_expires_logs_early_fails() -> None:
    # S3-LIFE-001 only asks that some rule is in range. S3-RET-001 checks every rule.
    document = compliant_document()
    _audit_rules(document).append(
        {
            "id": "sneaky-short-expiry",
            "status": "Enabled",
            "filter": [{"prefix": "cloudtrail/AWSLogs/"}],
            "expiration": [{"days": 1}],
            "noncurrent_version_expiration": [{"noncurrent_days": 1}],
        }
    )
    assessed = _assess(document)
    assert _statuses(assessed, "S3-RET-001") == {"fail"}


def test_expiration_by_date_fails() -> None:
    document = compliant_document()
    _audit_rules(document).append(
        {
            "id": "date-expiry",
            "status": "Enabled",
            "expiration": [{"date": "2027-01-01T00:00:00Z", "days": None}],
        }
    )
    assert _statuses(_assess(document), "S3-RET-001") == {"fail"}


def test_disabled_short_rule_does_not_fail_retention() -> None:
    document = compliant_document()
    _audit_rules(document).append({"id": "off", "status": "Disabled", "expiration": [{"days": 1}]})
    assessed = _assess(document)
    assert _statuses(assessed, "S3-RET-001") == {"pass"}
    # S3-LIFE-001 still rejects any rule that is not Enabled.
    assert _statuses(assessed, "S3-LIFE-001", "audit_logs") == {"fail"}


def test_noncurrent_shorter_than_current_fails() -> None:
    document = compliant_document()
    _audit_rules(document)[1]["expiration"] = [{"days": 730}]
    _audit_rules(document)[1]["noncurrent_version_expiration"] = [{"noncurrent_days": 400}]
    assert _statuses(_assess(document), "S3-RET-001") == {"fail"}


def test_unknown_noncurrent_days_is_unknown() -> None:
    document = compliant_document()
    resource = _resource(document, "aws_s3_bucket_lifecycle_configuration.audit_logs")
    resource["change"]["after"]["rule"][1]["noncurrent_version_expiration"] = [{}]
    resource["change"]["after_unknown"] = {
        "rule": [{}, {"noncurrent_version_expiration": [{"noncurrent_days": True}]}]
    }
    assert _statuses(_assess(document), "S3-RET-001") == {"unknown"}


# Object Lock (opt-in on the audit bucket)


@pytest.mark.parametrize("mode", ["GOVERNANCE", "COMPLIANCE"])
def test_object_lock_with_retention_passes(mode: str) -> None:
    assessed = _assess(object_lock_document(mode=mode))
    assert _statuses(assessed, "S3-LOCK-001", "audit_logs") == {"pass"}
    assert assessed["summary"]["result"] == "pass"


def test_object_lock_short_retention_fails() -> None:
    assessed = _assess(object_lock_document(days=30))
    assert _statuses(assessed, "S3-LOCK-001", "audit_logs") == {"fail"}


def test_object_lock_years_count_toward_floor() -> None:
    document = object_lock_document()
    rule = _after(document, "aws_s3_bucket_object_lock_configuration.audit_logs[0]")["rule"]
    rule[0]["default_retention"] = [{"days": None, "mode": "GOVERNANCE", "years": 1}]
    assert _statuses(_assess(document), "S3-LOCK-001", "audit_logs") == {"pass"}


def test_object_lock_bad_mode_fails() -> None:
    assessed = _assess(object_lock_document(mode="NONE"))
    assert _statuses(assessed, "S3-LOCK-001", "audit_logs") == {"fail"}


def test_object_lock_without_default_retention_fails() -> None:
    document = object_lock_document()
    _drop(document, "aws_s3_bucket_object_lock_configuration")
    assert _statuses(_assess(document), "S3-LOCK-001", "audit_logs") == {"fail"}


def test_object_lock_config_on_unlocked_bucket_fails() -> None:
    document = object_lock_document()
    _after(document, "aws_s3_bucket.audit_logs")["object_lock_enabled"] = False
    assert _statuses(_assess(document), "S3-LOCK-001", "audit_logs") == {"fail"}


def test_workload_object_lock_still_must_be_off() -> None:
    document = compliant_document()
    _after(document, "aws_s3_bucket.workload_data")["object_lock_enabled"] = True
    assert _statuses(_assess(document), "S3-LOCK-001", "workload_data") == {"fail"}


# CloudTrail S3 data events


def _set_data(document: dict, data: list) -> None:
    _after(document, "aws_cloudtrail.audit_logs")["event_selector"][0]["data_resource"] = data


def test_no_data_events_now_fails() -> None:
    document = compliant_document()
    _set_data(document, [])
    assert _statuses(_assess(document), "CT-DATA-001") == {"fail"}


def test_audit_bucket_as_data_resource_fails() -> None:
    document = compliant_document()
    _set_data(
        document,
        [
            {
                "type": "AWS::S3::Object",
                "values": [f"{DATA_BUCKET_ARN}/", f"{LOGS_BUCKET_ARN}/"],
            }
        ],
    )
    assert _statuses(_assess(document), "CT-DATA-001") == {"fail"}


def test_all_buckets_data_resource_fails() -> None:
    document = compliant_document()
    _set_data(document, [{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]}])
    assert _statuses(_assess(document), "CT-DATA-001") == {"fail"}


def test_wrong_data_resource_type_fails() -> None:
    document = compliant_document()
    _set_data(document, [{"type": "AWS::Lambda::Function", "values": [f"{DATA_BUCKET_ARN}/"]}])
    assert _statuses(_assess(document), "CT-DATA-001") == {"fail"}


def test_unknown_data_values_are_unknown() -> None:
    document = compliant_document()
    resource = _resource(document, "aws_cloudtrail.audit_logs")
    resource["change"]["after"]["event_selector"][0]["data_resource"] = [
        {"type": "AWS::S3::Object"}
    ]
    resource["change"]["after_unknown"] = {
        "event_selector": [{"data_resource": [{"values": True}]}]
    }
    assert _statuses(_assess(document), "CT-DATA-001") == {"unknown"}


# KMS key policy scope


def _statement(policy: dict, sid: str) -> dict:
    for statement in policy["Statement"]:
        if statement["Sid"] == sid:
            return statement
    raise KeyError(sid)


def test_workload_key_encrypt_and_reencrypt_fail() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.workload_data")
    _statement(policy, "AllowWorkloadRoleUse")["Action"] = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:ReEncrypt*",
    ]
    _write_policy(document, "aws_kms_key.workload_data", policy)
    assessed = _assess(document)
    assert _statuses(assessed, "KMS-SCOPE-001", "workload_data") == {"fail"}
    assert _statuses(assessed, "KMS-POL-001", "workload_data") == {"fail"}


def test_extra_wildcard_principal_key_statement_fails() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.audit_logs")
    policy["Statement"].append(
        {
            "Sid": "Extra",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {"StringEquals": {"kms:CallerAccount": "123456789012"}},
        }
    )
    _write_policy(document, "aws_kms_key.audit_logs", policy)
    assert _statuses(_assess(document), "KMS-SCOPE-001", "audit_logs") == {"fail"}


def test_unconditioned_auditor_decrypt_fails_scope() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.audit_logs")
    _statement(policy, "AllowAuditorDecrypt").pop("Condition")
    _write_policy(document, "aws_kms_key.audit_logs", policy)
    assert _statuses(_assess(document), "KMS-SCOPE-001", "audit_logs") == {"fail"}


def test_admin_action_for_auditor_fails_scope() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.audit_logs")
    _statement(policy, "AllowAuditorDecrypt")["Action"] = ["kms:Decrypt", "kms:PutKeyPolicy"]
    _write_policy(document, "aws_kms_key.audit_logs", policy)
    assert _statuses(_assess(document), "KMS-SCOPE-001", "audit_logs") == {"fail"}


def test_auditor_decrypt_without_via_service_fails_policy() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.audit_logs")
    _statement(policy, "AllowAuditorDecrypt")["Condition"] = {
        "Null": {"kms:EncryptionContext:aws:cloudtrail:arn": "false"}
    }
    _write_policy(document, "aws_kms_key.audit_logs", policy)
    assessed = _assess(document)
    assert _statuses(assessed, "KMS-POL-001", "audit_logs") == {"fail"}
    # The statement is still conditioned, so KMS-SCOPE-001 alone does not catch it.
    assert _statuses(assessed, "KMS-SCOPE-001", "audit_logs") == {"pass"}
    assert AUDITOR_ROLE_ARN in json.dumps(policy)


# IAM tamper actions


@pytest.mark.parametrize(
    ("address", "action"),
    [
        ("aws_iam_role_policy.workload_operator", "s3:Put*"),
        ("aws_iam_role_policy.workload_operator", "*"),
        ("aws_iam_role_policy.auditor", "cloudtrail:StopLogging"),
        ("aws_iam_role_policy.auditor", "kms:ScheduleKeyDeletion"),
        ("aws_iam_role_policy.auditor", "S3:PUTLIFECYCLECONFIGURATION"),
    ],
)
def test_tamper_action_in_role_policy_fails(address: str, action: str) -> None:
    document = compliant_document()
    policy = _policy(document, address)
    policy["Statement"].append(
        {"Sid": "Extra", "Effect": "Allow", "Action": action, "Resource": "*"}
    )
    _write_policy(document, address, policy)
    role = address.split(".", 1)[1]
    assert _statuses(_assess(document), "IAM-TAMPER-001", role) == {"fail"}


def test_tamper_action_under_deny_is_not_a_finding() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_iam_role_policy.auditor")
    policy["Statement"].append(
        {"Sid": "DenyStop", "Effect": "Deny", "Action": "cloudtrail:StopLogging", "Resource": "*"}
    )
    _write_policy(document, "aws_iam_role_policy.auditor", policy)
    assert _statuses(_assess(document), "IAM-TAMPER-001", "auditor") == {"pass"}
