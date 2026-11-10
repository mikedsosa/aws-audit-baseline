"""Crafted plans that must not receive a pass."""

import json

from aws_baseline_evidence.cli import assess_bytes
from tests.fixture_factory import compliant_document, dumps


def _status_for(assessed: dict, rule_id: str, address_part: str) -> str:
    matches = [
        item
        for item in assessed["findings"]
        if item["rule_id"] == rule_id and address_part in ",".join(item["resource_addresses"])
    ]
    assert matches, rule_id
    return matches[0]["status"]


def _statuses(document: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for finding in document["findings"]:
        found.setdefault(finding["rule_id"], set()).add(finding["status"])
    return found


def _assess(document: dict) -> dict:
    return assess_bytes(dumps(document))


def _policy_field(address: str) -> str:
    if address.startswith("aws_iam_role."):
        return "assume_role_policy"
    return "policy"


def _policy(document: dict, address: str) -> dict:
    field = _policy_field(address)
    for resource in document["resource_changes"]:
        if resource["address"] == address:
            return json.loads(resource["change"]["after"][field])
    raise KeyError(address)


def _write_policy(document: dict, address: str, policy: dict) -> None:
    field = _policy_field(address)
    for resource in document["resource_changes"]:
        if resource["address"] == address:
            resource["change"]["after"][field] = json.dumps(policy)
            return
    raise KeyError(address)


def test_cloudtrail_allow_with_an_extra_star_principal_fails() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_s3_bucket_policy.audit_logs")
    for statement in policy["Statement"]:
        if statement["Sid"] == "AWSCloudTrailWrite20150319":
            statement["Principal"] = {"AWS": "*", "Service": "cloudtrail.amazonaws.com"}
    _write_policy(document, "aws_s3_bucket_policy.audit_logs", policy)
    statuses = _statuses(_assess(document))
    assert "pass" not in statuses["CT-S3POL-001"]
    assert "fail" in statuses["CT-S3POL-001"]


def test_trust_policy_with_an_extra_identity_fails() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_iam_role.workload_operator")
    policy["Statement"][0]["Principal"]["Federated"] = "*"
    _write_policy(document, "aws_iam_role.workload_operator", policy)
    status = _status_for(_assess(document), "IAM-TRUST-001", "workload_operator")
    assert status == "fail"


def test_kms_cloudtrail_principal_star_fails() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_kms_key.audit_logs")
    for statement in policy["Statement"]:
        if statement["Sid"] == "AllowCloudTrailDecrypt":
            statement["Principal"] = {"AWS": "*", "Service": "cloudtrail.amazonaws.com"}
    _write_policy(document, "aws_kms_key.audit_logs", policy)
    status = _status_for(_assess(document), "KMS-POL-001", "audit_logs")
    assert status == "fail"


def test_excluded_management_event_sources_fail() -> None:
    document = compliant_document()
    for resource in document["resource_changes"]:
        if resource["address"] == "aws_cloudtrail.audit_logs":
            resource["change"]["after"]["event_selector"][0]["exclude_management_event_sources"] = [
                "kms.amazonaws.com"
            ]
    statuses = _statuses(_assess(document))
    assert "pass" not in statuses["CT-DATA-001"]
    assert "fail" in statuses["CT-DATA-001"]


def test_missing_explicit_sse_kms_deny_fails() -> None:
    document = compliant_document()
    drop = {
        "DenyCloudTrailIncorrectEncryptionHeader",
        "DenyIncorrectEncryptionHeader",
        "DenyNonCloudTrailIncorrectEncryptionHeader",
    }
    for address in ("aws_s3_bucket_policy.workload_data", "aws_s3_bucket_policy.audit_logs"):
        policy = _policy(document, address)
        policy["Statement"] = [
            statement for statement in policy["Statement"] if statement.get("Sid") not in drop
        ]
        _write_policy(document, address, policy)
    assessed = _assess(document)
    assert _status_for(assessed, "S3-SSE-001", "workload_data") == "fail"
    assert _status_for(assessed, "S3-SSE-001", "audit_logs") == "fail"


def test_auditor_object_wildcard_outside_the_log_prefix_fails() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_iam_role_policy.auditor")
    for statement in policy["Statement"]:
        if statement["Sid"] == "ReadAuditObjects":
            statement["Resource"] = "arn:aws:s3:::studybase-123456789012-logs/*"
    _write_policy(document, "aws_iam_role_policy.auditor", policy)
    status = _status_for(_assess(document), "IAM-PERM-001", "auditor")
    assert status == "fail"


def _set_effect(document: dict, address: str, sid: str, effect: str) -> None:
    policy = _policy(document, address)
    for statement in policy["Statement"]:
        if statement.get("Sid") == sid:
            statement["Effect"] = effect
    _write_policy(document, address, policy)


def test_cloudtrail_decrypt_deny_is_not_a_grant() -> None:
    document = compliant_document()
    _set_effect(document, "aws_kms_key.audit_logs", "AllowCloudTrailDecrypt", "Deny")
    status = _status_for(_assess(document), "KMS-POL-001", "audit_logs")
    assert status == "fail"


def test_auditor_decrypt_deny_is_not_a_grant() -> None:
    document = compliant_document()
    _set_effect(document, "aws_kms_key.audit_logs", "AllowAuditorDecrypt", "Deny")
    status = _status_for(_assess(document), "KMS-POL-001", "audit_logs")
    assert status == "fail"


def test_workload_key_deny_is_not_a_grant() -> None:
    document = compliant_document()
    _set_effect(document, "aws_kms_key.workload_data", "AllowWorkloadRoleUse", "Deny")
    status = _status_for(_assess(document), "KMS-POL-001", "workload_data")
    assert status == "fail"


def test_not_action_not_resource_and_not_principal_do_not_pass() -> None:
    not_action = compliant_document()
    policy = _policy(not_action, "aws_kms_key.audit_logs")
    policy["Statement"][0]["NotAction"] = "kms:Delete*"
    _write_policy(not_action, "aws_kms_key.audit_logs", policy)
    assessed = _assess(not_action)
    assert _status_for(assessed, "KMS-POL-001", "audit_logs") == "unknown"
    assert assessed["summary"]["result"] != "pass"

    not_resource = compliant_document()
    policy = _policy(not_resource, "aws_iam_role_policy.auditor")
    policy["Statement"][0]["NotResource"] = "arn:aws:s3:::somewhere-else"
    _write_policy(not_resource, "aws_iam_role_policy.auditor", policy)
    assessed = _assess(not_resource)
    assert _status_for(assessed, "IAM-PERM-001", "auditor") == "unknown"
    assert assessed["summary"]["result"] != "pass"

    not_principal = compliant_document()
    policy = _policy(not_principal, "aws_s3_bucket_policy.audit_logs")
    policy["Statement"][0]["NotPrincipal"] = {"Service": "ec2.amazonaws.com"}
    _write_policy(not_principal, "aws_s3_bucket_policy.audit_logs", policy)
    assessed = _assess(not_principal)
    assert _status_for(assessed, "CT-S3POL-001", "audit_logs") == "unknown"
    assert assessed["summary"]["result"] != "pass"


def test_audit_bucket_allows_cloudtrail_aes256_and_keeps_other_callers_on_kms() -> None:
    document = compliant_document()
    assessed = _assess(document)
    assert _status_for(assessed, "S3-SSE-001", "workload_data") == "pass"
    assert _status_for(assessed, "S3-SSE-001", "audit_logs") == "pass"
    workload = _policy(document, "aws_s3_bucket_policy.workload_data")
    workload_deny = next(
        statement
        for statement in workload["Statement"]
        if statement["Sid"] == "DenyIncorrectEncryptionHeader"
    )
    assert (
        workload_deny["Condition"]["StringNotEquals"]["s3:x-amz-server-side-encryption"]
        == "aws:kms"
    )
    audit = _policy(document, "aws_s3_bucket_policy.audit_logs")
    cloudtrail_deny = next(
        statement
        for statement in audit["Statement"]
        if statement["Sid"] == "DenyCloudTrailIncorrectEncryptionHeader"
    )
    assert set(
        cloudtrail_deny["Condition"]["StringNotEquals"]["s3:x-amz-server-side-encryption"]
    ) == {
        "AES256",
        "aws:kms",
    }
    assert cloudtrail_deny["Principal"] == {"Service": "cloudtrail.amazonaws.com"}

    kms_only = compliant_document()
    policy = _policy(kms_only, "aws_s3_bucket_policy.audit_logs")
    for statement in policy["Statement"]:
        if statement["Sid"] == "DenyCloudTrailIncorrectEncryptionHeader":
            statement["Condition"]["StringNotEquals"]["s3:x-amz-server-side-encryption"] = "aws:kms"
    _write_policy(kms_only, "aws_s3_bucket_policy.audit_logs", policy)
    assert _status_for(_assess(kms_only), "S3-SSE-001", "audit_logs") == "fail"


def test_non_cloudtrail_deny_uses_string_not_equals_if_exists() -> None:
    document = compliant_document()
    policy = _policy(document, "aws_s3_bucket_policy.audit_logs")
    statement = next(
        item
        for item in policy["Statement"]
        if item["Sid"] == "DenyNonCloudTrailIncorrectEncryptionHeader"
    )
    assert statement["Condition"]["StringNotEqualsIfExists"] == {
        "aws:PrincipalServiceName": "cloudtrail.amazonaws.com"
    }
    assert "aws:PrincipalServiceName" not in statement["Condition"]["StringNotEquals"]
    assert _status_for(_assess(document), "S3-SSE-001", "audit_logs") == "pass"

    plain = compliant_document()
    policy = _policy(plain, "aws_s3_bucket_policy.audit_logs")
    for item in policy["Statement"]:
        if item["Sid"] == "DenyNonCloudTrailIncorrectEncryptionHeader":
            item["Condition"] = {
                "StringNotEquals": {
                    "aws:PrincipalServiceName": "cloudtrail.amazonaws.com",
                    "s3:x-amz-server-side-encryption": "aws:kms",
                }
            }
    _write_policy(plain, "aws_s3_bucket_policy.audit_logs", policy)
    assert _status_for(_assess(plain), "S3-SSE-001", "audit_logs") == "fail"


def test_audit_delete_deny_has_no_break_glass() -> None:
    document = compliant_document()
    assert _status_for(_assess(document), "S3-AUDIT-DEL-001", "audit_logs") == "pass"
    removed = compliant_document()
    policy = _policy(removed, "aws_s3_bucket_policy.audit_logs")
    policy["Statement"] = [
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") != "DenyAuditObjectDelete"
    ]
    _write_policy(removed, "aws_s3_bucket_policy.audit_logs", policy)
    assert _status_for(_assess(removed), "S3-AUDIT-DEL-001", "audit_logs") == "fail"
    exempt = compliant_document()
    policy = _policy(exempt, "aws_s3_bucket_policy.audit_logs")
    for statement in policy["Statement"]:
        if statement.get("Sid") == "DenyAuditObjectDelete":
            statement["Condition"] = {
                "ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/BreakGlass"}
            }
    _write_policy(exempt, "aws_s3_bucket_policy.audit_logs", policy)
    assert _status_for(_assess(exempt), "S3-AUDIT-DEL-001", "audit_logs") == "fail"


def test_unknown_encryption_key_is_not_a_pass() -> None:
    document = compliant_document()
    for resource in document["resource_changes"]:
        if resource["address"] == "aws_s3_bucket_server_side_encryption_configuration.audit_logs":
            resource["change"]["after_unknown"] = {
                "rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": True}]}]
            }
    assessed = _assess(document)
    audit = [
        item
        for item in assessed["findings"]
        if item["rule_id"] == "S3-ENC-001" and "audit_logs" in ",".join(item["resource_addresses"])
    ]
    assert audit and audit[0]["status"] == "unknown"
    assert assessed["summary"]["result"] != "pass"
