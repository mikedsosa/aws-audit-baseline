"""Build plan-shaped JSON fixtures.

These documents are synthetic. They are not terraform show output and they are
not evidence that an AWS account exists.
"""

from __future__ import annotations

import copy
import json
from typing import Any

ACCOUNT = "123456789012"
REGION = "us-east-1"
PARTITION = "aws"
PREFIX = "studybase"
TRAIL = f"{PREFIX}-management"
DATA_BUCKET = f"{PREFIX}-{ACCOUNT}-data"
LOGS_BUCKET = f"{PREFIX}-{ACCOUNT}-logs"
DATA_KEY = "11111111-1111-4111-8111-111111111111"
LOGS_KEY = "22222222-2222-4222-8222-222222222222"
DATA_KEY_ARN = f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:key/{DATA_KEY}"
LOGS_KEY_ARN = f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:key/{LOGS_KEY}"
DATA_ALIAS = f"alias/{PREFIX}-data"
LOGS_ALIAS = f"alias/{PREFIX}-logs"
DATA_ALIAS_ARN = f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:{DATA_ALIAS}"
LOGS_ALIAS_ARN = f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:{LOGS_ALIAS}"
TRAIL_ARN = f"arn:{PARTITION}:cloudtrail:{REGION}:{ACCOUNT}:trail/{TRAIL}"
DATA_BUCKET_ARN = f"arn:{PARTITION}:s3:::{DATA_BUCKET}"
LOGS_BUCKET_ARN = f"arn:{PARTITION}:s3:::{LOGS_BUCKET}"
WORKLOAD_ROLE = f"{PREFIX}-workload-operator"
AUDITOR_ROLE = f"{PREFIX}-auditor"
WORKLOAD_ROLE_ARN = f"arn:{PARTITION}:iam::{ACCOUNT}:role/{WORKLOAD_ROLE}"
AUDITOR_ROLE_ARN = f"arn:{PARTITION}:iam::{ACCOUNT}:role/{AUDITOR_ROLE}"
WORKLOAD_USER = f"arn:{PARTITION}:iam::{ACCOUNT}:user/ExampleWorkloadOperator"
AUDITOR_USER = f"arn:{PARTITION}:iam::{ACCOUNT}:user/ExampleAuditor"
ROOT = f"arn:{PARTITION}:iam::{ACCOUNT}:root"


def compliant_document() -> dict[str, Any]:
    resources = [
        _bucket("workload_data", DATA_BUCKET, DATA_BUCKET_ARN, "workload-data"),
        _bucket("audit_logs", LOGS_BUCKET, LOGS_BUCKET_ARN, "audit-logs"),
        _account_public_access(),
        _public_access("workload_data", DATA_BUCKET),
        _public_access("audit_logs", LOGS_BUCKET),
        _ownership("workload_data", DATA_BUCKET),
        _ownership("audit_logs", LOGS_BUCKET),
        _versioning("workload_data", DATA_BUCKET),
        _versioning("audit_logs", LOGS_BUCKET),
        _encryption("workload_data", DATA_BUCKET, DATA_ALIAS_ARN),
        _encryption("audit_logs", LOGS_BUCKET, LOGS_ALIAS_ARN),
        _lifecycle(
            "workload_data",
            DATA_BUCKET,
            [
                {
                    "id": "abort-incomplete-multipart-uploads",
                    "status": "Enabled",
                    "abort_incomplete_multipart_upload": [{"days_after_initiation": 7}],
                },
                {
                    "id": "expire-noncurrent-versions",
                    "status": "Enabled",
                    "noncurrent_version_expiration": [{"noncurrent_days": 30}],
                },
            ],
        ),
        _lifecycle(
            "audit_logs",
            LOGS_BUCKET,
            [
                {
                    "id": "abort-incomplete-multipart-uploads",
                    "status": "Enabled",
                    "abort_incomplete_multipart_upload": [{"days_after_initiation": 7}],
                },
                {
                    "id": "expire-audit-objects",
                    "status": "Enabled",
                    "expiration": [{"days": 365}],
                    "noncurrent_version_expiration": [{"noncurrent_days": 365}],
                },
            ],
        ),
        _bucket_policy("workload_data", DATA_BUCKET, _workload_bucket_policy()),
        _bucket_policy("audit_logs", LOGS_BUCKET, _audit_bucket_policy()),
        _key("workload_data", DATA_KEY, DATA_KEY_ARN, "workload-data", _workload_key_policy()),
        _key("audit_logs", LOGS_KEY, LOGS_KEY_ARN, "audit-logs", _audit_key_policy()),
        _alias("workload_data", DATA_ALIAS, DATA_ALIAS_ARN, DATA_KEY),
        _alias("audit_logs", LOGS_ALIAS, LOGS_ALIAS_ARN, LOGS_KEY),
        _trail(),
        _role(
            "workload_operator",
            WORKLOAD_ROLE,
            WORKLOAD_ROLE_ARN,
            "workload-operator",
            _trust(WORKLOAD_USER),
        ),
        _role("auditor", AUDITOR_ROLE, AUDITOR_ROLE_ARN, "auditor", _trust(AUDITOR_USER)),
        _role_policy(
            "workload_operator", WORKLOAD_ROLE, "workload-app-prefix", _workload_role_policy()
        ),
        _role_policy("auditor", AUDITOR_ROLE, "audit-read", _auditor_role_policy()),
    ]
    return _document(resources, "compliant")


def unknown_document() -> dict[str, Any]:
    document = compliant_document()
    document["_aws_baseline_fixture"]["label"] = "unknown"
    _mask(document, "aws_s3_bucket_public_access_block.workload_data", ("block_public_acls",))
    _mask(document, "aws_s3_bucket_policy.audit_logs", ("policy",))
    _mask(document, "aws_cloudtrail.audit_logs", ("enable_log_file_validation",))
    _mask(document, "aws_kms_key.workload_data", ("enable_key_rotation",))
    _mask(document, "aws_kms_alias.audit_logs", ("target_key_id",))
    return document


def noncompliant_document() -> dict[str, Any]:
    document = compliant_document()
    document["_aws_baseline_fixture"]["label"] = "noncompliant"
    _after(document, "aws_s3_bucket_public_access_block.workload_data")["block_public_acls"] = False
    _after(document, "aws_s3_bucket.audit_logs")["force_destroy"] = True
    _after(document, "aws_s3_bucket.workload_data")["object_lock_enabled"] = True
    _after(document, "aws_s3_bucket_versioning.audit_logs")["versioning_configuration"] = [
        {"status": "Suspended"}
    ]
    _after(document, "aws_s3_bucket_ownership_controls.workload_data")["rule"] = [
        {"object_ownership": "ObjectWriter"}
    ]
    encryption = _after(
        document, "aws_s3_bucket_server_side_encryption_configuration.workload_data"
    )
    encryption["rule"] = [
        {
            "apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}],
            "bucket_key_enabled": False,
        }
    ]
    _after(document, "aws_kms_key.audit_logs")["enable_key_rotation"] = False
    _after(document, "aws_kms_key.audit_logs")["deletion_window_in_days"] = 7
    _after(document, "aws_kms_key.workload_data")["multi_region"] = True
    trail = _after(document, "aws_cloudtrail.audit_logs")
    trail["is_organization_trail"] = True
    trail["is_multi_region_trail"] = False
    trail["enable_log_file_validation"] = False
    trail["s3_bucket_name"] = DATA_BUCKET
    trail["kms_key_id"] = DATA_ALIAS_ARN
    trail["event_selector"] = [
        {
            "read_write_type": "All",
            "include_management_events": True,
            "data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]}],
        }
    ]
    _after(document, "aws_iam_role.workload_operator")["assume_role_policy"] = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "TrustedHumanUser",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    _after(document, "aws_iam_role_policy.workload_operator")["policy"] = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Admin",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
    )
    _after(document, "aws_s3_bucket_policy.workload_data")["policy"] = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"{DATA_BUCKET_ARN}/*",
                }
            ],
        }
    )
    document["resource_changes"].append(
        _change(
            "aws_instance.demo",
            "aws_instance",
            "demo",
            {"ami": "ami-00000000000000000", "instance_type": "t3.micro"},
        )
    )
    document["output_changes"]["deployment_status"]["change"]["after"] = "deployed"
    return document


def missing_public_access_document() -> dict[str, Any]:
    document = compliant_document()
    document["_aws_baseline_fixture"]["label"] = "missing-public-access"
    document["resource_changes"] = [
        resource
        for resource in document["resource_changes"]
        if resource["type"] != "aws_s3_bucket_public_access_block"
    ]
    document["configuration"]["root_module"]["resources"] = [
        resource
        for resource in document["configuration"]["root_module"]["resources"]
        if resource["type"] != "aws_s3_bucket_public_access_block"
    ]
    return document


def absent_force_destroy_document() -> dict[str, Any]:
    document = compliant_document()
    document["_aws_baseline_fixture"]["label"] = "absent-force-destroy"
    for name in ("workload_data", "audit_logs"):
        after = _after(document, f"aws_s3_bucket.{name}")
        after.pop("force_destroy", None)
    return document


def dumps(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _document(resources: list[dict[str, Any]], label: str) -> dict[str, Any]:
    return {
        "_aws_baseline_fixture": {
            "kind": "synthetic",
            "label": label,
            "not_deployed_aws": True,
            "note": "Hand-built plan-shaped JSON. Not terraform show output and not a deployed AWS account.",
        },
        "format_version": "1.2",
        "terraform_version": "synthetic",
        "resource_changes": resources,
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": resource["address"],
                        "mode": "managed",
                        "type": resource["type"],
                        "name": resource["name"],
                    }
                    for resource in resources
                ]
            }
        },
        "output_changes": {
            "deployment_status": {
                "change": {
                    "actions": ["create"],
                    "after": "not-deployed-by-this-draft",
                    "after_unknown": {},
                    "before": None,
                }
            }
        },
    }


def _change(address: str, type_name: str, name: str, after: dict[str, Any]) -> dict[str, Any]:
    return {
        "address": address,
        "change": {
            "actions": ["create"],
            "after": after,
            "after_unknown": {},
            "before": None,
        },
        "mode": "managed",
        "name": name,
        "type": type_name,
    }


def _tags(component: str) -> dict[str, str]:
    return {
        "BaselineComponent": component,
        "BaselineStack": "private-audit-baseline",
        "DraftStatus": "not-deployed",
    }


def _bucket(name: str, bucket: str, arn: str, component: str) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket.{name}",
        "aws_s3_bucket",
        name,
        {
            "arn": arn,
            "bucket": bucket,
            "force_destroy": False,
            "id": bucket,
            "object_lock_enabled": False,
            "tags": _tags(component),
        },
    )


def _account_public_access() -> dict[str, Any]:
    return _change(
        "aws_s3_account_public_access_block.account",
        "aws_s3_account_public_access_block",
        "account",
        {
            "account_id": ACCOUNT,
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    )


def object_lock_document(mode: str = "GOVERNANCE", days: int = 365) -> dict[str, Any]:
    """Compliant document with the opt-in audit Object Lock turned on."""
    document = compliant_document()
    document["_aws_baseline_fixture"]["label"] = "object-lock"
    _after(document, "aws_s3_bucket.audit_logs")["object_lock_enabled"] = True
    lock = _change(
        "aws_s3_bucket_object_lock_configuration.audit_logs[0]",
        "aws_s3_bucket_object_lock_configuration",
        "audit_logs",
        {
            "bucket": LOGS_BUCKET,
            "object_lock_enabled": "Enabled",
            "rule": [{"default_retention": [{"days": days, "mode": mode, "years": None}]}],
        },
    )
    document["resource_changes"].append(lock)
    document["configuration"]["root_module"]["resources"].append(
        {
            "address": "aws_s3_bucket_object_lock_configuration.audit_logs",
            "mode": "managed",
            "type": "aws_s3_bucket_object_lock_configuration",
            "name": "audit_logs",
        }
    )
    return document


def _public_access(name: str, bucket: str) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_public_access_block.{name}",
        "aws_s3_bucket_public_access_block",
        name,
        {
            "block_public_acls": True,
            "block_public_policy": True,
            "bucket": bucket,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    )


def _ownership(name: str, bucket: str) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_ownership_controls.{name}",
        "aws_s3_bucket_ownership_controls",
        name,
        {"bucket": bucket, "rule": [{"object_ownership": "BucketOwnerEnforced"}]},
    )


def _versioning(name: str, bucket: str) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_versioning.{name}",
        "aws_s3_bucket_versioning",
        name,
        {"bucket": bucket, "versioning_configuration": [{"status": "Enabled"}]},
    )


def _encryption(name: str, bucket: str, alias_arn: str) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_server_side_encryption_configuration.{name}",
        "aws_s3_bucket_server_side_encryption_configuration",
        name,
        {
            "bucket": bucket,
            "rule": [
                {
                    "apply_server_side_encryption_by_default": [
                        {"kms_master_key_id": alias_arn, "sse_algorithm": "aws:kms"}
                    ],
                    "bucket_key_enabled": True,
                }
            ],
        },
    )


def _lifecycle(name: str, bucket: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_lifecycle_configuration.{name}",
        "aws_s3_bucket_lifecycle_configuration",
        name,
        {"bucket": bucket, "rule": rules},
    )


def _bucket_policy(name: str, bucket: str, policy: dict[str, Any]) -> dict[str, Any]:
    return _change(
        f"aws_s3_bucket_policy.{name}",
        "aws_s3_bucket_policy",
        name,
        {"bucket": bucket, "policy": json.dumps(policy)},
    )


def _key(
    name: str, key_id: str, arn: str, component: str, policy: dict[str, Any]
) -> dict[str, Any]:
    return _change(
        f"aws_kms_key.{name}",
        "aws_kms_key",
        name,
        {
            "arn": arn,
            "customer_master_key_spec": "SYMMETRIC_DEFAULT",
            "deletion_window_in_days": 30,
            "enable_key_rotation": True,
            "id": key_id,
            "is_enabled": True,
            "key_id": key_id,
            "key_usage": "ENCRYPT_DECRYPT",
            "multi_region": False,
            "policy": json.dumps(policy),
            "rotation_period_in_days": 365,
            "tags": _tags(component),
        },
    )


def _alias(name: str, alias: str, arn: str, target: str) -> dict[str, Any]:
    return _change(
        f"aws_kms_alias.{name}",
        "aws_kms_alias",
        name,
        {"arn": arn, "name": alias, "target_key_id": target},
    )


def _trail() -> dict[str, Any]:
    return _change(
        "aws_cloudtrail.audit_logs",
        "aws_cloudtrail",
        "audit_logs",
        {
            "advanced_event_selector": [],
            "arn": TRAIL_ARN,
            "enable_log_file_validation": True,
            "enable_logging": True,
            "event_selector": [
                {
                    "data_resource": [
                        {"type": "AWS::S3::Object", "values": [f"{DATA_BUCKET_ARN}/"]}
                    ],
                    "exclude_management_event_sources": [],
                    "include_management_events": True,
                    "read_write_type": "All",
                }
            ],
            "include_global_service_events": True,
            "insight_selector": [],
            "is_multi_region_trail": True,
            "is_organization_trail": False,
            "kms_key_id": LOGS_ALIAS_ARN,
            "name": TRAIL,
            "s3_bucket_name": LOGS_BUCKET,
            "s3_key_prefix": "cloudtrail",
            "tags": _tags("audit-logs"),
        },
    )


def _role(
    name: str, role_name: str, arn: str, component: str, trust: dict[str, Any]
) -> dict[str, Any]:
    return _change(
        f"aws_iam_role.{name}",
        "aws_iam_role",
        name,
        {
            "arn": arn,
            "assume_role_policy": json.dumps(trust),
            "id": role_name,
            "max_session_duration": 3600,
            "name": role_name,
            "tags": _tags(component),
        },
    )


def _role_policy(
    name: str, role_name: str, policy_name: str, policy: dict[str, Any]
) -> dict[str, Any]:
    return _change(
        f"aws_iam_role_policy.{name}",
        "aws_iam_role_policy",
        name,
        {"name": policy_name, "policy": json.dumps(policy), "role": role_name},
    )


def _trust(user_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustedHumanUser",
                "Effect": "Allow",
                "Principal": {"AWS": [user_arn]},
                "Action": "sts:AssumeRole",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ],
    }


def _encryption_header_deny(bucket_arn: str) -> dict[str, Any]:
    return {
        "Sid": "DenyIncorrectEncryptionHeader",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": f"{bucket_arn}/*",
        "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}},
    }


def _workload_bucket_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [_tls_deny(DATA_BUCKET_ARN), _encryption_header_deny(DATA_BUCKET_ARN)],
    }


def _audit_bucket_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": LOGS_BUCKET_ARN,
                "Condition": {"StringEquals": {"aws:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{LOGS_BUCKET_ARN}/cloudtrail/AWSLogs/{ACCOUNT}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": TRAIL_ARN,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    }
                },
            },
            _tls_deny(LOGS_BUCKET_ARN),
            _audit_non_cloudtrail_encryption_deny(LOGS_BUCKET_ARN),
            _audit_cloudtrail_encryption_deny(LOGS_BUCKET_ARN),
            _audit_delete_deny(LOGS_BUCKET_ARN),
        ],
    }


def _audit_non_cloudtrail_encryption_deny(bucket_arn: str) -> dict[str, Any]:
    return {
        "Sid": "DenyNonCloudTrailIncorrectEncryptionHeader",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": f"{bucket_arn}/*",
        "Condition": {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"},
            "StringNotEqualsIfExists": {"aws:PrincipalServiceName": "cloudtrail.amazonaws.com"},
        },
    }


def _audit_cloudtrail_encryption_deny(bucket_arn: str) -> dict[str, Any]:
    return {
        "Sid": "DenyCloudTrailIncorrectEncryptionHeader",
        "Effect": "Deny",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": f"{bucket_arn}/*",
        "Condition": {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]}
        },
    }


def _audit_delete_deny(bucket_arn: str) -> dict[str, Any]:
    return {
        "Sid": "DenyAuditObjectDelete",
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
        "Resource": f"{bucket_arn}/*",
    }


def _tls_deny(bucket_arn: str) -> dict[str, Any]:
    return {
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [bucket_arn, f"{bucket_arn}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }


def _workload_key_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            _root_statement(),
            {
                "Sid": "AllowWorkloadRoleUse",
                "Effect": "Allow",
                "Principal": {"AWS": WORKLOAD_ROLE_ARN},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:EncryptionContext:aws:s3:arn": DATA_BUCKET_ARN,
                        "kms:ViaService": f"s3.{REGION}.amazonaws.com",
                    }
                },
            },
        ],
    }


def _audit_key_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            _root_statement(),
            {
                "Sid": "AllowCloudTrailEncryptLogs",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:GenerateDataKey*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceArn": TRAIL_ARN},
                    "StringLike": {
                        "kms:EncryptionContext:aws:cloudtrail:arn": (
                            f"arn:{PARTITION}:cloudtrail:*:{ACCOUNT}:trail/*"
                        )
                    },
                },
            },
            {
                "Sid": "AllowCloudTrailDescribeKey",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:DescribeKey",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AllowCloudTrailDecrypt",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
            {
                "Sid": "AllowAuditorDecrypt",
                "Effect": "Allow",
                "Principal": {"AWS": AUDITOR_ROLE_ARN},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "Null": {"kms:EncryptionContext:aws:cloudtrail:arn": "false"},
                    "StringEquals": {"kms:ViaService": f"s3.{REGION}.amazonaws.com"},
                },
            },
        ],
    }


def _root_statement() -> dict[str, Any]:
    return {
        "Sid": "EnableAccountRootAdministration",
        "Effect": "Allow",
        "Principal": {"AWS": ROOT},
        "Action": "kms:*",
        "Resource": "*",
    }


def _workload_role_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadAndDeleteAppPrefix",
                "Effect": "Allow",
                "Action": ["s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject"],
                "Resource": f"{DATA_BUCKET_ARN}/app/*",
            },
            {
                "Sid": "PutEncryptedAppPrefix",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"{DATA_BUCKET_ARN}/app/*",
                "Condition": {"StringEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}},
            },
            {
                "Sid": "ListAppPrefix",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": DATA_BUCKET_ARN,
                "Condition": {"StringLike": {"s3:prefix": ["app/*", "app/"]}},
            },
        ],
    }


def _auditor_role_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadAuditObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": f"{LOGS_BUCKET_ARN}/cloudtrail/*",
            },
            {
                "Sid": "ListAuditBucket",
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                "Resource": LOGS_BUCKET_ARN,
                "Condition": {"StringLike": {"s3:prefix": ["cloudtrail/*", "cloudtrail/"]}},
            },
            {
                "Sid": "ReadTrail",
                "Effect": "Allow",
                "Action": [
                    "cloudtrail:GetEventSelectors",
                    "cloudtrail:GetTrail",
                    "cloudtrail:GetTrailStatus",
                ],
                "Resource": TRAIL_ARN,
            },
            {
                "Sid": "ReadTrailAccountApis",
                "Effect": "Allow",
                "Action": [
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:ListTrails",
                    "cloudtrail:LookupEvents",
                ],
                "Resource": "*",
            },
        ],
    }


def _after(document: dict[str, Any], address: str) -> dict[str, Any]:
    for resource in document["resource_changes"]:
        if resource["address"] == address:
            return resource["change"]["after"]
    raise KeyError(address)


def _mask(document: dict[str, Any], address: str, path: tuple[str, ...]) -> None:
    for resource in document["resource_changes"]:
        if resource["address"] != address:
            continue
        unknown = resource["change"]["after_unknown"]
        node = unknown
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = True
        return
    raise KeyError(address)


def with_provisioner(command: str) -> dict[str, Any]:
    document = copy.deepcopy(compliant_document())
    document["_aws_baseline_fixture"]["label"] = "provisioner"
    document["configuration"]["root_module"]["resources"][0]["provisioners"] = [
        {"type": "local-exec", "expressions": {"command": {"constant_value": command}}}
    ]
    return document
