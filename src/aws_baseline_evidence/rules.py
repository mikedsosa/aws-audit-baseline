"""Security invariants for the private workload bucket and audit trail.

A missing attribute is a fail for a required control. An unknown planned value
is unknown. Neither result is a pass.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from aws_baseline_evidence.catalog import (
    ACCOUNT_SCOPED_TRAIL_READS,
    AUDIT_RETENTION_FLOOR_DAYS,
    AUDITOR_ACTIONS,
    BUCKET_COMPONENTS,
    DEPLOYMENT_STATUS,
    KEY_COMPONENTS,
    KEY_USE_ACTIONS,
    OBJECT_LOCK_MODES,
    ROLE_COMPONENTS,
    SUPPORTED_TYPES,
    TAMPER_ACTIONS,
)
from aws_baseline_evidence.lookup import attr, shown
from aws_baseline_evidence.plan import ParsedPlan, Resource
from aws_baseline_evidence.policy import (
    actions_of,
    bool_condition,
    condition_values,
    parse_policy,
    principal_services,
    principals_aws,
    resources_of,
    statements,
)
from aws_baseline_evidence.report import Finding

_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]+$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_USER = re.compile(r"^arn:[^:]+:iam::[0-9]{12}:user/[A-Za-z0-9+=,.@_-]+$")
_BPA = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
_COMPONENT_TYPES = frozenset({"aws_cloudtrail", "aws_iam_role", "aws_kms_key", "aws_s3_bucket"})
_REQUIRED = (
    ("aws_s3_bucket", "workload-data"),
    ("aws_s3_bucket", "audit-logs"),
    ("aws_kms_key", "workload-data"),
    ("aws_kms_key", "audit-logs"),
    ("aws_iam_role", "workload-operator"),
    ("aws_iam_role", "auditor"),
    ("aws_cloudtrail", "audit-logs"),
)
# The S3 SSE-KMS page lists kms:GenerateDataKey for PutObject and kms:Decrypt
# for GetObject and multipart upload. Read 2026-11-13.
_WORKLOAD_KEY_ACTIONS = frozenset({"kms:Decrypt", "kms:GenerateDataKey"})
_AUDIT_SIDS = frozenset(
    {
        "AWSCloudTrailAclCheck20150319",
        "AWSCloudTrailWrite20150319",
        "DenyAuditObjectDelete",
        "DenyCloudTrailIncorrectEncryptionHeader",
        "DenyInsecureTransport",
        "DenyNonCloudTrailIncorrectEncryptionHeader",
    }
)
_WORKLOAD_SIDS = frozenset({"DenyIncorrectEncryptionHeader", "DenyInsecureTransport"})
_WORKLOAD_POLICY_SIDS = frozenset(
    {"ListAppPrefix", "PutEncryptedAppPrefix", "ReadAndDeleteAppPrefix"}
)
_AUDITOR_POLICY_SIDS = frozenset(
    {"ListAuditBucket", "ReadAuditObjects", "ReadTrail", "ReadTrailAccountApis"}
)
_WORKLOAD_KEY_SIDS = frozenset({"AllowWorkloadRoleUse", "EnableAccountRootAdministration"})
_AUDIT_KEY_SIDS = frozenset(
    {
        "AllowAuditorDecrypt",
        "AllowCloudTrailDecrypt",
        "AllowCloudTrailDescribeKey",
        "AllowCloudTrailEncryptLogs",
        "EnableAccountRootAdministration",
    }
)


def finding(rule_id: str, status: str, addresses: tuple[str, ...], reason: str) -> Finding:
    return Finding(rule_id, status, tuple(sorted(set(addresses))), reason)


def combine(parts: list[tuple[str, str]]) -> tuple[str, str]:
    fails = [reason for status, reason in parts if status == "fail"]
    unknowns = [reason for status, reason in parts if status == "unknown"]
    if fails:
        return "fail", " ".join(fails)
    if unknowns:
        return "unknown", " ".join(unknowns)
    return "pass", " ".join(reason for _status, reason in parts)


@dataclass
class Scope:
    accounts: set[str] = field(default_factory=set)
    regions: set[str] = field(default_factory=set)
    partitions: set[str] = field(default_factory=set)
    trail_arns: set[str] = field(default_factory=set)

    @property
    def account(self) -> str | None:
        if len(self.accounts) == 1:
            return next(iter(self.accounts))
        return None

    @property
    def region(self) -> str | None:
        if len(self.regions) == 1:
            return next(iter(self.regions))
        return None

    @property
    def partition(self) -> str | None:
        if len(self.partitions) == 1:
            return next(iter(self.partitions))
        return None

    @property
    def trail_arn(self) -> str | None:
        if len(self.trail_arns) == 1:
            return next(iter(self.trail_arns))
        return None

    @property
    def conflict(self) -> bool:
        return (
            len(self.accounts) > 1
            or len(self.regions) > 1
            or len(self.partitions) > 1
            or len(self.trail_arns) > 1
        )

    @property
    def complete(self) -> bool:
        return (
            self.account is not None
            and self.region is not None
            and self.partition is not None
            and not self.conflict
        )


@dataclass
class Inventory:
    grouped: dict[tuple[str, str], list[Resource]]
    unknown_tagged: list[Resource]
    unexpected: list[Resource]
    active: list[Resource]

    def one(self, type_name: str, component: str) -> Resource | None:
        items = self.grouped.get((type_name, component), [])
        if len(items) == 1:
            return items[0]
        return None


def evaluate(plan: ParsedPlan) -> list[Finding]:
    active = [
        resource
        for resource in plan.resources
        if resource.mode == "managed" and not resource.removed
    ]
    inventory = _inventory(active)
    scope = _scope(active, inventory)
    findings = [
        _base_components(inventory),
        _base_scope(scope),
        _disclaimer(plan),
        _provisioners(plan),
        _unsupported(plan),
        _account_bpa(active, scope),
        *_per_bucket(inventory, active, scope),
        *_per_key(inventory, active, scope),
        _key_separation(inventory, active),
        *_trail(inventory, active, scope),
        *_roles(inventory, active, scope),
    ]
    return findings


def _inventory(active: list[Resource]) -> Inventory:
    grouped: dict[tuple[str, str], list[Resource]] = {key: [] for key in _REQUIRED}
    unknown_tagged: list[Resource] = []
    unexpected: list[Resource] = []
    for resource in active:
        if resource.type_name not in _COMPONENT_TYPES:
            continue
        state, tag = attr(resource, ("tags", "BaselineComponent"))
        key = (resource.type_name, tag)
        if state == "unknown":
            unknown_tagged.append(resource)
        elif state == "known" and key in grouped:
            grouped[key].append(resource)
        else:
            unexpected.append(resource)
    return Inventory(grouped, unknown_tagged, unexpected, active)


def _base_components(inventory: Inventory) -> Finding:
    missing = False
    ambiguous = False
    duplicate = False
    addresses: list[str] = []
    for key, items in inventory.grouped.items():
        type_name, component = key
        addresses.extend(resource.address for resource in items)
        unknowns = [
            resource for resource in inventory.unknown_tagged if resource.type_name == type_name
        ]
        if len(items) > 1:
            duplicate = True
        elif len(items) == 0 and unknowns:
            ambiguous = True
        elif len(items) == 0:
            missing = True
            addresses.append(f"missing:{type_name}:{component}")
    if inventory.unexpected:
        addresses.extend(resource.address for resource in inventory.unexpected)
    if inventory.unknown_tagged:
        ambiguous = True
        addresses.extend(resource.address for resource in inventory.unknown_tagged)
    if duplicate or missing or inventory.unexpected:
        return finding(
            "BASE-COMP-001",
            "fail",
            tuple(addresses),
            "the planned end state does not contain exactly one of each baseline component",
        )
    if ambiguous:
        return finding(
            "BASE-COMP-001",
            "unknown",
            tuple(addresses),
            "a component tag is unknown, so the inventory cannot be proved",
        )
    return finding(
        "BASE-COMP-001",
        "pass",
        tuple(addresses),
        "the planned end state has one tagged workload bucket, audit bucket, workload key, audit key, workload role, auditor role, and trail",
    )


def _base_scope(scope: Scope) -> Finding:
    if scope.conflict:
        return finding(
            "BASE-SCOPE-001",
            "fail",
            (),
            "account, Region, partition, or trail ARN values in the plan disagree",
        )
    if not scope.complete or scope.trail_arn is None:
        return finding(
            "BASE-SCOPE-001",
            "unknown",
            (),
            "account, Region, partition, or trail ARN could not be read from known plan values",
        )
    return finding(
        "BASE-SCOPE-001",
        "pass",
        (),
        f"known ARNs agree on account {scope.account}, region {scope.region}, and partition {scope.partition}",
    )


def _disclaimer(plan: ParsedPlan) -> Finding:
    state, value = plan.outputs.get("deployment_status", ("absent", None))
    if state == "known" and value == DEPLOYMENT_STATUS:
        return finding(
            "DISCLAIM-001",
            "pass",
            ("output.deployment_status",),
            "deployment_status is the draft disclaimer; it does not prove an AWS deployment",
        )
    if state == "unknown":
        return finding(
            "DISCLAIM-001",
            "unknown",
            ("output.deployment_status",),
            "deployment_status is unknown",
        )
    return finding(
        "DISCLAIM-001",
        "fail",
        ("output.deployment_status",),
        "deployment_status is absent or is not the draft disclaimer",
    )


def _provisioners(plan: ParsedPlan) -> Finding:
    if not plan.provisioners_known:
        return finding(
            "PROV-001",
            "unknown",
            (),
            "the plan has no configuration block, so provisioners cannot be ruled out",
        )
    if plan.provisioner_addresses:
        return finding(
            "PROV-001",
            "fail",
            plan.provisioner_addresses,
            "the plan contains provisioners; this tool does not execute them and will not pass the plan",
        )
    return finding(
        "PROV-001",
        "pass",
        (),
        "the plan configuration has no provisioners",
    )


def _unsupported(plan: ParsedPlan) -> Finding:
    rows = [
        resource
        for resource in plan.resources
        if resource.mode != "managed" or resource.type_name not in SUPPORTED_TYPES
    ]
    if not rows:
        return finding(
            "UNSUPPORTED-TYPE-001",
            "pass",
            (),
            "every resource_changes entry is a supported managed type",
        )
    return finding(
        "UNSUPPORTED-TYPE-001",
        "unknown",
        tuple(resource.address for resource in rows),
        "the plan contains resource types or modes this checker does not assess",
    )


def _per_bucket(inventory: Inventory, active: list[Resource], scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for component in BUCKET_COMPONENTS:
        bucket = inventory.one("aws_s3_bucket", component)
        findings.extend(
            [
                _bpa(component, bucket, active),
                _encryption(component, bucket, inventory, active, scope),
                _versioning(component, bucket, active),
                _ownership(component, bucket, active),
                _transport(component, bucket, active, scope),
                _sse_header(component, bucket, active, scope),
                _policy_sids(component, bucket, active),
                _force_destroy(component, bucket),
                _object_lock(component, bucket, active),
                _lifecycle(component, bucket, active),
            ]
        )
    findings.append(_audit_delete(inventory, active, scope))
    findings.append(_retention(inventory.one("aws_s3_bucket", "audit-logs"), active))
    return findings


def _per_key(inventory: Inventory, active: list[Resource], scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    for component in KEY_COMPONENTS:
        key = inventory.one("aws_kms_key", component)
        findings.extend(
            [
                _rotation(component, key),
                _deletion_window(component, key),
                _key_spec(component, key),
                _key_policy(component, key, inventory, scope),
                _key_scope(component, key, scope),
                _alias(component, key, active),
            ]
        )
    return findings


def _missing(rule_id: str, component: str, reason: str) -> Finding:
    return finding(rule_id, "fail", (f"missing:{component}",), reason)


def _bpa(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "S3-BPA-001"
    if bucket is None:
        return _missing(
            rule_id,
            component,
            f"{component} bucket is absent, so public access block is not present",
        )
    matched, unresolved = _children(active, bucket, "aws_s3_bucket_public_access_block")
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        reason = (
            "public access block bucket attribute is unknown"
            if status == "unknown"
            else "the bucket does not have exactly one public access block"
        )
        return finding(rule_id, status, (bucket.address,), reason)
    block = matched[0]
    parts: list[tuple[str, str]] = []
    for flag in _BPA:
        state, value = attr(block, (flag,))
        if state == "known" and value is True:
            continue
        if state == "unknown":
            parts.append(("unknown", f"{flag} is unknown"))
        elif state == "absent":
            parts.append(("fail", f"{flag} is absent"))
        else:
            parts.append(("fail", f"{flag} is {shown(value)}"))
    if not parts:
        return finding(
            rule_id,
            "pass",
            (bucket.address, block.address),
            "all four public access block settings are explicitly true",
        )
    status, reason = combine(parts)
    return finding(rule_id, status, (bucket.address, block.address), reason)


def _encryption(
    component: str,
    bucket: Resource | None,
    inventory: Inventory,
    active: list[Resource],
    scope: Scope,
) -> Finding:
    rule_id = "S3-ENC-001"
    if bucket is None:
        return _missing(
            rule_id, component, f"{component} bucket is absent, so encryption is not present"
        )
    matched, unresolved = _children(
        active, bucket, "aws_s3_bucket_server_side_encryption_configuration"
    )
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        return finding(
            rule_id,
            status,
            (bucket.address,),
            "encryption configuration is missing or its bucket attribute is unknown",
        )
    config = matched[0]
    parts: list[tuple[str, str]] = []
    state, algorithm = _flex(
        config, ("rule", 0, "apply_server_side_encryption_by_default", 0), "sse_algorithm"
    )
    if state == "known" and algorithm == "aws:kms":
        pass
    elif state == "unknown":
        parts.append(("unknown", "sse_algorithm is unknown"))
    elif state == "absent":
        parts.append(("fail", "sse_algorithm is absent"))
    else:
        parts.append(("fail", f"sse_algorithm is {shown(algorithm)}"))
    state, bucket_key = _flex(config, ("rule", 0), "bucket_key_enabled")
    if state == "known" and bucket_key is True:
        pass
    elif state == "unknown":
        parts.append(("unknown", "bucket_key_enabled is unknown"))
    elif state == "absent":
        parts.append(("fail", "bucket_key_enabled is absent"))
    else:
        parts.append(("fail", f"bucket_key_enabled is {shown(bucket_key)}"))
    state, key_id = _flex(
        config, ("rule", 0, "apply_server_side_encryption_by_default", 0), "kms_master_key_id"
    )
    link_state, alias = _alias_for(inventory, active, component)
    if state != "known" or not isinstance(key_id, str):
        parts.append(
            (state if state == "unknown" else "fail", "kms_master_key_id is not a known string")
        )
    elif link_state == "unknown":
        parts.append(("unknown", "the alias target for this component key is unknown"))
    elif link_state != "known" or alias is None:
        parts.append(("fail", "no alias is bound to this component key"))
    elif not _alias_id_matches(alias, key_id, scope):
        parts.append(("fail", "kms_master_key_id does not match this component alias"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (bucket.address, config.address), reason)
    return finding(
        rule_id,
        "pass",
        (bucket.address, config.address),
        "default encryption is SSE-KMS with a bucket key and this component's alias",
    )


def _versioning(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    return _block_status(
        "S3-VER-001",
        component,
        bucket,
        active,
        "aws_s3_bucket_versioning",
        ("versioning_configuration", 0, "status"),
        "Enabled",
        "versioning status is Enabled",
    )


def _ownership(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    return _block_status(
        "S3-OWN-001",
        component,
        bucket,
        active,
        "aws_s3_bucket_ownership_controls",
        ("rule", 0, "object_ownership"),
        "BucketOwnerEnforced",
        "object ownership is BucketOwnerEnforced",
    )


def _block_status(
    rule_id: str,
    component: str,
    bucket: Resource | None,
    active: list[Resource],
    type_name: str,
    path: tuple[Any, ...],
    expected: str,
    pass_reason: str,
) -> Finding:
    if bucket is None:
        return _missing(rule_id, component, f"{component} bucket is absent")
    matched, unresolved = _children(active, bucket, type_name)
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        return finding(rule_id, status, (bucket.address,), f"{type_name} is missing or not linked")
    state, value = attr(matched[0], path)
    if state == "absent":
        state, value = attr(matched[0], _without_index(path))
    if state == "known" and value == expected:
        return finding(rule_id, "pass", (bucket.address, matched[0].address), pass_reason)
    if state == "unknown":
        return finding(
            rule_id, "unknown", (bucket.address, matched[0].address), f"{path[-1]} is unknown"
        )
    if state == "absent":
        return finding(
            rule_id, "fail", (bucket.address, matched[0].address), f"{path[-1]} is absent"
        )
    return finding(
        rule_id,
        "fail",
        (bucket.address, matched[0].address),
        f"{path[-1]} is {shown(value)}",
    )


def _transport(
    component: str, bucket: Resource | None, active: list[Resource], scope: Scope
) -> Finding:
    rule_id = "S3-TLS-001"
    loaded = _bucket_policy(component, bucket, active, scope)
    if isinstance(loaded, Finding):
        return finding(rule_id, loaded.status, loaded.resource_addresses, loaded.reason)
    policy_resource, parsed, bucket_arn = loaded
    assert bucket is not None
    state, items = statements(parsed)
    if state != "known" or items is None:
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "bucket policy statements are not assessable",
        )
    expected = {bucket_arn, f"{bucket_arn}/*"}
    for statement in items:
        if statement.get("Effect") != "Deny" or statement.get("Sid") != "DenyInsecureTransport":
            continue
        action_state, actions = actions_of(statement)
        resource_state, resources = resources_of(statement)
        principal_state, principals = principals_aws(statement.get("Principal"))
        transport_state, transport = bool_condition(statement, "aws:SecureTransport")
        checks = [action_state, resource_state, principal_state, transport_state]
        if "unknown" in checks:
            return finding(
                rule_id,
                "unknown",
                (bucket.address, policy_resource.address),
                "TLS deny statement is only partly known",
            )
        if (
            actions == {"s3:*"}
            and resources == expected
            and principals == {"*"}
            and transport == {"false"}
        ):
            return finding(
                rule_id,
                "pass",
                (bucket.address, policy_resource.address),
                "bucket policy denies s3:* when aws:SecureTransport is false",
            )
    return finding(
        rule_id,
        "fail",
        (bucket.address, policy_resource.address),
        "bucket policy has no matching deny for insecure transport",
    )


def _policy_sids(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "S3-POLICY-001"
    loaded = _policy_statements(component, bucket, active)
    if isinstance(loaded, Finding):
        return finding(rule_id, loaded.status, loaded.resource_addresses, loaded.reason)
    _bucket, policy_resource, items = loaded
    expected = _WORKLOAD_SIDS if component == "workload-data" else _AUDIT_SIDS
    sids = [item.get("Sid") for item in items]
    if any(not isinstance(sid, str) for sid in sids):
        return finding(
            rule_id,
            "unknown",
            (_bucket.address, policy_resource.address),
            "a bucket policy statement has no Sid",
        )
    if set(sids) != expected or len(sids) != len(expected):
        return finding(
            rule_id,
            "fail",
            (_bucket.address, policy_resource.address),
            "bucket policy statement IDs are not the assessed set",
        )
    return finding(
        rule_id,
        "pass",
        (_bucket.address, policy_resource.address),
        "bucket policy statement IDs match the assessed set",
    )


def _force_destroy(component: str, bucket: Resource | None) -> Finding:
    return _explicit_bool(
        "S3-DESTROY-001",
        component,
        bucket,
        "force_destroy",
        False,
        "force_destroy is explicitly false",
    )


def _object_lock(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "S3-LOCK-001"
    off = _explicit_bool(
        rule_id,
        component,
        bucket,
        "object_lock_enabled",
        False,
        "Object Lock is explicitly off; this pass is not an immutability control",
    )
    if bucket is None or component != "audit-logs":
        return off
    state, enabled = attr(bucket, ("object_lock_enabled",))
    matched, unresolved = _children(active, bucket, "aws_s3_bucket_object_lock_configuration")
    if state == "known" and enabled is False:
        if matched:
            return finding(
                rule_id,
                "fail",
                (bucket.address, *(item.address for item in matched)),
                "an Object Lock configuration targets a bucket created with object_lock_enabled false",
            )
        return off
    if state != "known" or enabled is not True:
        return off
    if unresolved and not matched:
        return finding(
            rule_id, "unknown", (bucket.address,), "Object Lock configuration bucket is unknown"
        )
    if len(matched) != 1:
        return finding(
            rule_id,
            "fail",
            (bucket.address,),
            "Object Lock is on but the bucket does not have exactly one default retention configuration",
        )
    config = matched[0]
    addresses = (bucket.address, config.address)
    parts: list[tuple[str, str]] = []
    rule_state, rules = attr(config, ("rule",))
    if rule_state == "unknown":
        return finding(rule_id, "unknown", addresses, "Object Lock rule is unknown")
    if rule_state != "known" or not isinstance(rules, list) or len(rules) != 1:
        return finding(rule_id, "fail", addresses, "Object Lock default retention rule is absent")
    retention = ("rule", 0, "default_retention", 0)
    mode_state, mode = _flex(config, retention, "mode")
    days_state, days = _flex(config, retention, "days")
    years_state, years = _flex(config, retention, "years")
    if mode_state == "unknown":
        parts.append(("unknown", "Object Lock mode is unknown"))
    elif mode not in OBJECT_LOCK_MODES:
        parts.append(("fail", f"Object Lock mode is {shown(mode)}"))
    if "unknown" in {days_state, years_state}:
        parts.append(("unknown", "Object Lock retention period is unknown"))
    else:
        total = 0
        if isinstance(days, int) and not isinstance(days, bool):
            total = days
        elif isinstance(years, int) and not isinstance(years, bool):
            total = years * 365
        if total < AUDIT_RETENTION_FLOOR_DAYS:
            parts.append(
                (
                    "fail",
                    f"Object Lock default retention is below {AUDIT_RETENTION_FLOOR_DAYS} days",
                )
            )
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, addresses, reason)
    return finding(
        rule_id,
        "pass",
        addresses,
        f"audit Object Lock default retention is {mode} for at least {AUDIT_RETENTION_FLOOR_DAYS} days; not verified against a live bucket",
    )


def _explicit_bool(
    rule_id: str,
    component: str,
    bucket: Resource | None,
    name: str,
    expected: bool,
    pass_reason: str,
) -> Finding:
    if bucket is None:
        return _missing(rule_id, component, f"{component} bucket is absent")
    state, value = attr(bucket, (name,))
    if state == "known" and value is expected:
        return finding(rule_id, "pass", (bucket.address,), pass_reason)
    if state == "unknown":
        return finding(rule_id, "unknown", (bucket.address,), f"{name} is unknown")
    if state == "absent":
        return finding(rule_id, "fail", (bucket.address,), f"{name} is absent")
    return finding(rule_id, "fail", (bucket.address,), f"{name} is {shown(value)}")


def _lifecycle(component: str, bucket: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "S3-LIFE-001"
    if bucket is None:
        return _missing(rule_id, component, f"{component} bucket is absent")
    matched, unresolved = _children(active, bucket, "aws_s3_bucket_lifecycle_configuration")
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        return finding(
            rule_id, status, (bucket.address,), "lifecycle configuration is missing or not linked"
        )
    lifecycle = matched[0]
    state, rules = attr(lifecycle, ("rule",))
    if state == "unknown":
        return finding(
            rule_id, "unknown", (bucket.address, lifecycle.address), "lifecycle rules are unknown"
        )
    if state != "known" or not isinstance(rules, list) or not rules:
        return finding(
            rule_id, "fail", (bucket.address, lifecycle.address), "lifecycle rules are absent"
        )
    parts: list[tuple[str, str]] = []
    abort_days: list[int] = []
    expire_days: list[int] = []
    noncurrent_days: list[int] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            parts.append(("unknown", "a lifecycle rule is not an object"))
            continue
        status_state, status = attr(lifecycle, ("rule", index, "status"))
        if status_state == "unknown":
            parts.append(("unknown", "a lifecycle rule status is unknown"))
        elif status != "Enabled":
            parts.append(("fail", "a lifecycle rule is not Enabled"))
        abort_state, abort = _flex(
            lifecycle,
            ("rule", index, "abort_incomplete_multipart_upload", 0),
            "days_after_initiation",
        )
        expire_state, expire = _flex(lifecycle, ("rule", index, "expiration", 0), "days")
        noncurrent_state, noncurrent = _flex(
            lifecycle, ("rule", index, "noncurrent_version_expiration", 0), "noncurrent_days"
        )
        for label, item_state, item_value, sink in (
            ("abort", abort_state, abort, abort_days),
            ("expiration", expire_state, expire, expire_days),
            ("noncurrent", noncurrent_state, noncurrent, noncurrent_days),
        ):
            if item_state == "unknown":
                parts.append(("unknown", f"{label} is unknown"))
            elif item_state == "known":
                if not isinstance(item_value, int):
                    parts.append(("fail", f"{label} is not an integer"))
                else:
                    sink.append(item_value)
    if not any(1 <= day <= 7 for day in abort_days):
        parts.append(("fail", "incomplete multipart upload abort is not in 1 through 7 days"))
    if component == "audit-logs":
        if not any(365 <= day <= 3650 for day in expire_days):
            parts.append(("fail", "audit object expiration is not in 365 through 3650 days"))
        if not noncurrent_days or not all(365 <= day <= 3650 for day in noncurrent_days):
            parts.append(("fail", "audit noncurrent expiration is not in 365 through 3650 days"))
    else:
        if expire_days:
            parts.append(("fail", "workload lifecycle expires current objects"))
        if not noncurrent_days or not all(7 <= day <= 90 for day in noncurrent_days):
            parts.append(("fail", "workload noncurrent expiration is not in 7 through 90 days"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (bucket.address, lifecycle.address), reason)
    return finding(
        rule_id,
        "pass",
        (bucket.address, lifecycle.address),
        "lifecycle matches the baseline retention and abort limits",
    )


def _rotation(component: str, key: Resource | None) -> Finding:
    rule_id = "KMS-ROT-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    parts: list[tuple[str, str]] = []
    state, enabled = attr(key, ("enable_key_rotation",))
    if state == "known" and enabled is True:
        pass
    elif state == "unknown":
        parts.append(("unknown", "enable_key_rotation is unknown"))
    elif state == "absent":
        parts.append(("fail", "enable_key_rotation is absent"))
    else:
        parts.append(("fail", f"enable_key_rotation is {shown(enabled)}"))
    state, period = attr(key, ("rotation_period_in_days",))
    if state == "known" and period == 365:
        pass
    elif state == "unknown":
        parts.append(("unknown", "rotation_period_in_days is unknown"))
    elif state == "absent":
        parts.append(("fail", "rotation_period_in_days is absent"))
    else:
        parts.append(("fail", f"rotation_period_in_days is {shown(period)}"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (key.address,), reason)
    return finding(rule_id, "pass", (key.address,), "key rotation is enabled with a 365 day period")


def _deletion_window(component: str, key: Resource | None) -> Finding:
    rule_id = "KMS-WIN-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    state, value = attr(key, ("deletion_window_in_days",))
    if state == "known" and value == 30:
        return finding(rule_id, "pass", (key.address,), "deletion window is 30 days")
    if state == "unknown":
        return finding(rule_id, "unknown", (key.address,), "deletion_window_in_days is unknown")
    if state == "absent":
        return finding(rule_id, "fail", (key.address,), "deletion_window_in_days is absent")
    return finding(rule_id, "fail", (key.address,), f"deletion_window_in_days is {shown(value)}")


def _key_spec(component: str, key: Resource | None) -> Finding:
    rule_id = "KMS-SPEC-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    expected = {
        "customer_master_key_spec": "SYMMETRIC_DEFAULT",
        "is_enabled": True,
        "key_usage": "ENCRYPT_DECRYPT",
        "multi_region": False,
    }
    parts: list[tuple[str, str]] = []
    for name, wanted in expected.items():
        state, value = attr(key, (name,))
        if state == "known" and value is wanted or (state == "known" and value == wanted):
            continue
        if state == "unknown":
            parts.append(("unknown", f"{name} is unknown"))
        elif state == "absent":
            parts.append(("fail", f"{name} is absent"))
        else:
            parts.append(("fail", f"{name} is {shown(value)}"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (key.address,), reason)
    return finding(
        rule_id, "pass", (key.address,), "key is an enabled single-Region symmetric encryption key"
    )


def _key_policy(
    component: str, key: Resource | None, inventory: Inventory, scope: Scope
) -> Finding:
    rule_id = "KMS-POL-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    state, raw = attr(key, ("policy",))
    if state == "unknown":
        return finding(rule_id, "unknown", (key.address,), "key policy is unknown")
    if state != "known":
        return finding(rule_id, "fail", (key.address,), "key policy is absent")
    parsed_state, parsed = parse_policy(raw)
    if parsed_state != "known" or parsed is None:
        return finding(rule_id, "unknown", (key.address,), "key policy is not assessable JSON")
    statement_state, items = statements(parsed)
    if statement_state != "known" or items is None:
        return finding(
            rule_id, "unknown", (key.address,), "key policy statements are not assessable"
        )
    by_sid, sid_problem = _by_sid(items)
    if sid_problem is not None:
        return finding(rule_id, sid_problem[0], (key.address,), sid_problem[1])
    expected = _WORKLOAD_KEY_SIDS if component == "workload-data" else _AUDIT_KEY_SIDS
    if set(by_sid) != expected:
        return finding(
            rule_id, "fail", (key.address,), "key policy statement IDs are not the assessed set"
        )
    if not scope.complete or scope.trail_arn is None:
        return finding(
            rule_id,
            "unknown",
            (key.address,),
            "key policy cannot be checked without account, region, and trail ARN",
        )
    parts = [_root_statement(by_sid["EnableAccountRootAdministration"], scope)]
    if component == "workload-data":
        parts.append(_workload_key_use(by_sid["AllowWorkloadRoleUse"], inventory, scope))
    else:
        parts.extend(
            [
                _cloudtrail_encrypt(by_sid["AllowCloudTrailEncryptLogs"], scope),
                _cloudtrail_describe(by_sid["AllowCloudTrailDescribeKey"], scope),
                _cloudtrail_decrypt(by_sid["AllowCloudTrailDecrypt"]),
                _auditor_decrypt(by_sid["AllowAuditorDecrypt"], inventory, scope),
            ]
        )
    status, reason = combine(parts)
    if status == "pass":
        reason = "key policy matches the baseline statements for this component"
    return finding(rule_id, status, (key.address,), reason)


def _alias(component: str, key: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "KMS-ALIAS-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    ids = _key_ids(key)
    aliases = [resource for resource in active if resource.type_name == "aws_kms_alias"]
    matched: list[Resource] = []
    unknown = False
    for alias_resource in aliases:
        target_state, target = attr(alias_resource, ("target_key_id",))
        if target_state == "unknown":
            unknown = True
        elif target_state == "known" and target in ids:
            matched.append(alias_resource)
    if unknown:
        return finding(rule_id, "unknown", (key.address,), "an alias target_key_id is unknown")
    if len(aliases) != 2 or len(matched) != 1:
        return finding(
            rule_id,
            "fail",
            (key.address,),
            "the plan does not have two aliases with exactly one targeting this component key",
        )
    name_state, name = attr(matched[0], ("name",))
    if name_state != "known" or not isinstance(name, str) or not name.startswith("alias/"):
        return finding(
            rule_id,
            "fail",
            (key.address, matched[0].address),
            "alias name is not a known alias/ name",
        )
    return finding(
        rule_id,
        "pass",
        (key.address, matched[0].address),
        "one alias targets this component key",
    )


def _key_separation(inventory: Inventory, active: list[Resource]) -> Finding:
    rule_id = "KMS-SEP-001"
    values: list[str] = []
    unknown = False
    addresses: list[str] = []
    for component in BUCKET_COMPONENTS:
        bucket = inventory.one("aws_s3_bucket", component)
        if bucket is None:
            return _missing(rule_id, component, f"{component} bucket is absent")
        addresses.append(bucket.address)
        matched, unresolved = _children(
            active, bucket, "aws_s3_bucket_server_side_encryption_configuration"
        )
        if unresolved or len(matched) != 1:
            unknown = True
            continue
        state, key_id = _flex(
            matched[0],
            ("rule", 0, "apply_server_side_encryption_by_default", 0),
            "kms_master_key_id",
        )
        if state == "known" and isinstance(key_id, str):
            values.append(key_id)
        else:
            unknown = True
    if len(values) == 2 and values[0] == values[1]:
        return finding(rule_id, "fail", tuple(addresses), "both buckets use the same KMS key id")
    if len(values) == 2 and not unknown:
        return finding(rule_id, "pass", tuple(addresses), "the buckets use different KMS key ids")
    return finding(rule_id, "unknown", tuple(addresses), "one or both KMS key ids are unknown")


def _trail(inventory: Inventory, active: list[Resource], scope: Scope) -> list[Finding]:
    trail = inventory.one("aws_cloudtrail", "audit-logs")
    return [
        _trail_flags(trail),
        _trail_destination(trail, inventory, active, scope),
        _trail_bucket_policy(trail, inventory, active, scope),
        _trail_data(trail, inventory, scope),
    ]


def _trail_flags(trail: Resource | None) -> Finding:
    rule_id = "CT-FLAG-001"
    if trail is None:
        return _missing(rule_id, "audit-logs", "trail is absent")
    required_true = (
        "enable_log_file_validation",
        "enable_logging",
        "include_global_service_events",
        "is_multi_region_trail",
    )
    parts: list[tuple[str, str]] = []
    for name in required_true:
        parts.append(_expect_bool(trail, name, True))
    parts.append(_expect_bool(trail, "is_organization_trail", False))
    parts = [part for part in parts if part is not None]
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (trail.address,), reason)
    return finding(
        rule_id,
        "pass",
        (trail.address,),
        "trail logging, validation, global events, and multi-Region delivery are explicit, and the trail is not an organization trail",
    )


def _expect_bool(resource: Resource, name: str, expected: bool) -> tuple[str, str] | None:
    state, value = attr(resource, (name,))
    if state == "known" and value is expected:
        return None
    if state == "unknown":
        return "unknown", f"{name} is unknown"
    if state == "absent":
        return "fail", f"{name} is absent"
    return "fail", f"{name} is {shown(value)}"


def _trail_destination(
    trail: Resource | None, inventory: Inventory, active: list[Resource], scope: Scope
) -> Finding:
    rule_id = "CT-DEST-001"
    if trail is None:
        return _missing(rule_id, "audit-logs", "trail is absent")
    bucket = inventory.one("aws_s3_bucket", "audit-logs")
    if bucket is None:
        return _missing(rule_id, "audit-logs", "audit bucket is absent")
    parts: list[tuple[str, str]] = []
    names = _bucket_name_set(bucket)
    state, bucket_name = attr(trail, ("s3_bucket_name",))
    if state == "known" and bucket_name in names:
        pass
    elif state == "unknown":
        parts.append(("unknown", "s3_bucket_name is unknown"))
    else:
        parts.append(("fail", "trail bucket is not the audit bucket"))
    state, prefix = attr(trail, ("s3_key_prefix",))
    if state == "known" and prefix == "cloudtrail":
        pass
    elif state == "unknown":
        parts.append(("unknown", "s3_key_prefix is unknown"))
    elif state == "absent":
        parts.append(("fail", "s3_key_prefix is absent"))
    else:
        parts.append(("fail", f"s3_key_prefix is {shown(prefix)}"))
    state, key_id = attr(trail, ("kms_key_id",))
    link_state, alias = _alias_for(inventory, active, "audit-logs")
    if state != "known" or not isinstance(key_id, str):
        parts.append(
            ("unknown" if state == "unknown" else "fail", "kms_key_id is not a known string")
        )
    elif link_state == "unknown":
        parts.append(("unknown", "audit alias target is unknown"))
    elif alias is None or not _alias_id_matches(alias, key_id, scope):
        parts.append(("fail", "trail KMS key is not the audit alias"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (trail.address, bucket.address), reason)
    return finding(
        rule_id,
        "pass",
        (trail.address, bucket.address),
        "trail destination is the audit bucket, cloudtrail prefix, and audit alias",
    )


def _trail_bucket_policy(
    trail: Resource | None, inventory: Inventory, active: list[Resource], scope: Scope
) -> Finding:
    rule_id = "CT-S3POL-001"
    if trail is None or scope.trail_arn is None or not scope.complete:
        return finding(
            rule_id,
            "unknown" if trail is not None else "fail",
            () if trail is None else (trail.address,),
            "trail destination policy cannot be proved from known values",
        )
    loaded = _policy_statements("audit-logs", inventory.one("aws_s3_bucket", "audit-logs"), active)
    if isinstance(loaded, Finding):
        return finding(rule_id, loaded.status, loaded.resource_addresses, loaded.reason)
    bucket, policy_resource, items = loaded
    by_sid, problem = _by_sid(items)
    if problem is not None:
        return finding(rule_id, problem[0], (bucket.address, policy_resource.address), problem[1])
    bucket_arn_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    if bucket_arn_state != "known" or bucket_arn is None or scope.account is None:
        return finding(rule_id, "unknown", (bucket.address,), "audit bucket ARN is unknown")
    acl = by_sid.get("AWSCloudTrailAclCheck20150319")
    write = by_sid.get("AWSCloudTrailWrite20150319")
    if acl is None or write is None:
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "CloudTrail bucket policy statements are absent",
        )
    expected_object = f"{bucket_arn}/cloudtrail/AWSLogs/{scope.account}/*"
    parts = [
        _expect_statement(
            acl,
            service="cloudtrail.amazonaws.com",
            actions={"s3:GetBucketAcl"},
            resources={bucket_arn},
            source=scope.trail_arn,
        ),
        _expect_statement(
            write,
            service="cloudtrail.amazonaws.com",
            actions={"s3:PutObject"},
            resources={expected_object},
            source=scope.trail_arn,
            acl="bucket-owner-full-control",
        ),
    ]
    status, reason = combine(parts)
    if status == "pass":
        reason = "CloudTrail can get the bucket ACL and put logs only for this trail ARN"
    return finding(
        rule_id, status, (bucket.address, policy_resource.address, trail.address), reason
    )


def _trail_data(trail: Resource | None, inventory: Inventory, scope: Scope) -> Finding:
    rule_id = "CT-DATA-001"
    if trail is None:
        return _missing(rule_id, "audit-logs", "trail is absent")
    parts: list[tuple[str, str]] = []
    state, selectors = attr(trail, ("event_selector",))
    if state == "absent":
        parts.append(("fail", "event_selector is absent"))
    elif state == "unknown":
        parts.append(("unknown", "event_selector is unknown"))
    elif (
        not isinstance(selectors, list) or len(selectors) != 1 or not isinstance(selectors[0], dict)
    ):
        parts.append(("fail", "event_selector is not one block"))
    else:
        include_state, include = attr(trail, ("event_selector", 0, "include_management_events"))
        read_state, read_write = attr(trail, ("event_selector", 0, "read_write_type"))
        data_state, data = attr(trail, ("event_selector", 0, "data_resource"))
        if (
            include_state == "known"
            and include is True
            and read_state == "known"
            and read_write == "All"
        ):
            pass
        elif "unknown" in {include_state, read_state}:
            parts.append(("unknown", "management event selector is unknown"))
        else:
            parts.append(("fail", "management event selector is not explicit"))
        if data_state == "absent":
            parts.append(
                ("fail", "data_resource is absent, so workload object access is not logged")
            )
        elif data_state == "unknown":
            parts.append(("unknown", "data_resource is unknown"))
        else:
            parts.append(_data_resources(trail, data, inventory, scope))
        excluded_state, excluded = attr(
            trail, ("event_selector", 0, "exclude_management_event_sources")
        )
        if excluded_state == "unknown":
            parts.append(("unknown", "exclude_management_event_sources is unknown"))
        elif excluded_state == "absent":
            parts.append(
                ("unknown", "exclude_management_event_sources is absent and is not assumed empty")
            )
        elif excluded not in ([], None):
            parts.append(("fail", "management event sources are excluded"))
    for name in ("advanced_event_selector", "insight_selector"):
        item_state, item = attr(trail, (name,))
        if item_state == "absent":
            parts.append(("unknown", f"{name} is absent and is not assumed empty"))
        elif item_state == "unknown":
            parts.append(("unknown", f"{name} is unknown"))
        elif item not in ([], None):
            parts.append(("fail", f"{name} is not empty"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (trail.address,), reason)
    return finding(
        rule_id,
        "pass",
        (trail.address,),
        "management events are explicit and the only data resource is S3 object events for the workload bucket; the audit bucket is not selected",
    )


def _data_resources(
    trail: Resource, data: object, inventory: Inventory, scope: Scope
) -> tuple[str, str]:
    bucket = inventory.one("aws_s3_bucket", "workload-data")
    audit = inventory.one("aws_s3_bucket", "audit-logs")
    if bucket is None or audit is None:
        return "fail", "a baseline bucket is absent, so data events cannot be matched"
    bucket_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    audit_state, audit_arn = _resource_arn(audit, scope, "s3")
    if bucket_state != "known" or audit_state != "known" or not bucket_arn or not audit_arn:
        return "unknown", "bucket ARNs for the data event selector are unknown"
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        return "fail", "data_resource is not exactly one S3 object selector"
    type_state, type_name = attr(trail, ("event_selector", 0, "data_resource", 0, "type"))
    values_state, values = attr(trail, ("event_selector", 0, "data_resource", 0, "values"))
    if "unknown" in {type_state, values_state}:
        return "unknown", "data_resource type or values are unknown"
    if type_name != "AWS::S3::Object":
        return "fail", f"data_resource type is {shown(type_name)}"
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        return "fail", "data_resource values are not a list of strings"
    if any(item.startswith(audit_arn) for item in values):
        return "fail", "the audit bucket is a data event resource, which logs log delivery"
    if values != [f"{bucket_arn}/"]:
        return "fail", "data_resource values are not exactly the workload bucket object prefix"
    return "pass", "workload bucket object events are selected"


def _roles(inventory: Inventory, active: list[Resource], scope: Scope) -> list[Finding]:
    findings = []
    for component in ROLE_COMPONENTS:
        role = inventory.one("aws_iam_role", component)
        findings.append(_trust(component, role, scope))
        findings.append(_session(component, role))
        findings.append(_permissions(component, role, inventory, active, scope))
        findings.append(_tamper(component, role, active))
    return findings


def _trust(component: str, role: Resource | None, scope: Scope) -> Finding:
    rule_id = "IAM-TRUST-001"
    if role is None:
        return _missing(rule_id, component, f"{component} role is absent")
    state, raw = attr(role, ("assume_role_policy",))
    if state == "unknown":
        return finding(rule_id, "unknown", (role.address,), "assume role policy is unknown")
    if state != "known":
        return finding(rule_id, "fail", (role.address,), "assume role policy is absent")
    parsed_state, parsed = parse_policy(raw)
    if parsed_state != "known" or parsed is None:
        return finding(
            rule_id, "unknown", (role.address,), "assume role policy is not assessable JSON"
        )
    statement_state, items = statements(parsed)
    if statement_state != "known" or items is None:
        return finding(
            rule_id, "unknown", (role.address,), "assume role statements are not assessable"
        )
    if len(items) != 1:
        return finding(
            rule_id,
            "fail",
            (role.address,),
            "assume role policy does not have exactly one statement",
        )
    statement = items[0]
    if statement.get("Sid") != "TrustedHumanUser" or statement.get("Effect") != "Allow":
        return finding(
            rule_id, "fail", (role.address,), "assume role statement is not the assessed allow"
        )
    action_state, actions = actions_of(statement)
    if not isinstance(statement.get("Principal"), dict) or set(statement["Principal"]) != {"AWS"}:
        return finding(
            rule_id,
            "fail",
            (role.address,),
            "trust principal includes an unexpected identity",
        )
    principal_state, principals = principals_aws(statement.get("Principal"))
    mfa_state, mfa = bool_condition(statement, "aws:MultiFactorAuthPresent")
    if "unknown" in {action_state, principal_state, mfa_state} or scope.account is None:
        return finding(
            rule_id, "unknown", (role.address,), "assume role trust cannot be fully read"
        )
    good_users = {
        principal
        for principal in principals
        if _USER.fullmatch(principal) and f":{scope.account}:" in principal
    }
    if (
        actions != {"sts:AssumeRole"}
        or mfa != {"true"}
        or not principals
        or good_users != principals
    ):
        return finding(
            rule_id,
            "fail",
            (role.address,),
            "trust policy is not limited to IAM users in this account with MFA",
        )
    return finding(
        rule_id,
        "pass",
        (role.address,),
        "trust policy allows only IAM users in this account and requires MFA",
    )


def _session(component: str, role: Resource | None) -> Finding:
    rule_id = "IAM-SESSION-001"
    if role is None:
        return _missing(rule_id, component, f"{component} role is absent")
    state, value = attr(role, ("max_session_duration",))
    if state == "known" and value == 3600:
        return finding(rule_id, "pass", (role.address,), "max_session_duration is 3600 seconds")
    if state == "unknown":
        return finding(rule_id, "unknown", (role.address,), "max_session_duration is unknown")
    if state == "absent":
        return finding(rule_id, "fail", (role.address,), "max_session_duration is absent")
    return finding(rule_id, "fail", (role.address,), f"max_session_duration is {shown(value)}")


def _permissions(
    component: str,
    role: Resource | None,
    inventory: Inventory,
    active: list[Resource],
    scope: Scope,
) -> Finding:
    rule_id = "IAM-PERM-001"
    if role is None:
        return _missing(rule_id, component, f"{component} role is absent")
    if not scope.complete or scope.trail_arn is None:
        return finding(
            rule_id, "unknown", (role.address,), "role permissions cannot be checked without scope"
        )
    names = _known_strings(role, ("name", "id"))
    matched = []
    unknown = False
    for policy in active:
        if policy.type_name != "aws_iam_role_policy":
            continue
        state, role_name = attr(policy, ("role",))
        if state == "unknown":
            unknown = True
        elif state == "known" and role_name in names:
            matched.append(policy)
    if unknown and len(matched) != 1:
        return finding(
            rule_id, "unknown", (role.address,), "inline policy role attribute is unknown"
        )
    if len(matched) != 1:
        return finding(
            rule_id, "fail", (role.address,), "the role does not have exactly one inline policy"
        )
    policy = matched[0]
    state, raw = attr(policy, ("policy",))
    if state != "known":
        return finding(
            rule_id,
            "unknown" if state == "unknown" else "fail",
            (role.address, policy.address),
            "inline policy is not known",
        )
    parsed_state, parsed = parse_policy(raw)
    if parsed_state != "known" or parsed is None:
        return finding(
            rule_id,
            "unknown",
            (role.address, policy.address),
            "inline policy is not assessable JSON",
        )
    statement_state, items = statements(parsed)
    if statement_state != "known" or items is None:
        return finding(
            rule_id,
            "unknown",
            (role.address, policy.address),
            "inline policy statements are not assessable",
        )
    by_sid, problem = _by_sid(items)
    if problem is not None:
        return finding(rule_id, problem[0], (role.address, policy.address), problem[1])
    if component == "workload-operator":
        return _workload_permissions(role, policy, by_sid, inventory, scope)
    return _auditor_permissions(role, policy, by_sid, inventory, scope)


def _workload_permissions(
    role: Resource,
    policy: Resource,
    by_sid: dict[str, dict[str, object]],
    inventory: Inventory,
    scope: Scope,
) -> Finding:
    rule_id = "IAM-PERM-001"
    if set(by_sid) != _WORKLOAD_POLICY_SIDS:
        return finding(
            rule_id,
            "fail",
            (role.address, policy.address),
            "workload policy statement IDs are not the assessed set",
        )
    bucket = inventory.one("aws_s3_bucket", "workload-data")
    logs = inventory.one("aws_s3_bucket", "audit-logs")
    if bucket is None or logs is None or scope.partition is None:
        return finding(rule_id, "unknown", (role.address,), "workload bucket scope is incomplete")
    bucket_arn_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    logs_state, logs_arn = _resource_arn(logs, scope, "s3")
    if (
        bucket_arn_state != "known"
        or logs_state != "known"
        or bucket_arn is None
        or logs_arn is None
    ):
        return finding(rule_id, "unknown", (role.address,), "bucket ARN is unknown")
    object_resource = f"{bucket_arn}/app/*"
    parts = [
        _actions_and_resource(
            by_sid["ReadAndDeleteAppPrefix"],
            {"s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject"},
            {object_resource},
        ),
        _actions_and_resource(by_sid["PutEncryptedAppPrefix"], {"s3:PutObject"}, {object_resource}),
        _actions_and_resource(by_sid["ListAppPrefix"], {"s3:ListBucket"}, {bucket_arn}),
    ]
    put = by_sid["PutEncryptedAppPrefix"]
    sse_state, sse = condition_values(put, "StringEquals", "s3:x-amz-server-side-encryption")
    if sse_state != "known" or sse != {"aws:kms"}:
        parts.append(
            ("fail" if sse_state == "known" else "unknown", "PutObject is not limited to aws:kms")
        )
    list_state, prefixes = condition_values(by_sid["ListAppPrefix"], "StringLike", "s3:prefix")
    if list_state != "known" or prefixes != {"app/*", "app/"}:
        parts.append(
            ("fail" if list_state == "known" else "unknown", "ListBucket prefix is not app/")
        )
    blob = str(by_sid)
    if logs_arn in blob or "kms:" in blob:
        parts.append(("fail", "workload policy references the audit bucket or KMS"))
    status, reason = combine([part for part in parts if part[0] != "pass"])
    if status == "pass" and not any(part[0] != "pass" for part in parts):
        return finding(
            rule_id,
            "pass",
            (role.address, policy.address),
            "workload policy is limited to the app prefix",
        )
    if not parts or all(part[0] == "pass" for part in parts):
        return finding(
            rule_id,
            "pass",
            (role.address, policy.address),
            "workload policy is limited to the app prefix",
        )
    return finding(rule_id, status, (role.address, policy.address), reason)


def _auditor_permissions(
    role: Resource,
    policy: Resource,
    by_sid: dict[str, dict[str, object]],
    inventory: Inventory,
    scope: Scope,
) -> Finding:
    rule_id = "IAM-PERM-001"
    if set(by_sid) != _AUDITOR_POLICY_SIDS:
        return finding(
            rule_id,
            "fail",
            (role.address, policy.address),
            "auditor policy statement IDs are not the assessed set",
        )
    logs = inventory.one("aws_s3_bucket", "audit-logs")
    data = inventory.one("aws_s3_bucket", "workload-data")
    if logs is None or data is None or scope.trail_arn is None:
        return finding(rule_id, "unknown", (role.address,), "auditor scope is incomplete")
    logs_state, logs_arn = _resource_arn(logs, scope, "s3")
    data_state, data_arn = _resource_arn(data, scope, "s3")
    if logs_state != "known" or data_state != "known" or logs_arn is None or data_arn is None:
        return finding(rule_id, "unknown", (role.address,), "bucket ARN is unknown")
    parts = [
        _actions_and_resource(
            by_sid["ReadAuditObjects"],
            {"s3:GetObject", "s3:GetObjectVersion"},
            {f"{logs_arn}/cloudtrail/*"},
        ),
        _actions_and_resource(
            by_sid["ListAuditBucket"], {"s3:ListBucket", "s3:ListBucketVersions"}, {logs_arn}
        ),
        _actions_and_resource(
            by_sid["ReadTrail"],
            {"cloudtrail:GetEventSelectors", "cloudtrail:GetTrail", "cloudtrail:GetTrailStatus"},
            {scope.trail_arn},
        ),
        _actions_and_resource(
            by_sid["ReadTrailAccountApis"], set(ACCOUNT_SCOPED_TRAIL_READS), {"*"}
        ),
    ]
    list_state, prefixes = condition_values(by_sid["ListAuditBucket"], "StringLike", "s3:prefix")
    if list_state != "known" or prefixes != {"cloudtrail/*", "cloudtrail/"}:
        parts.append(
            (
                "fail" if list_state == "known" else "unknown",
                "auditor list is not limited to the cloudtrail prefix",
            )
        )
    blob = str(by_sid)
    if (
        data_arn in blob
        or "s3:Delete" in blob
        or "cloudtrail:Delete" in blob
        or "cloudtrail:StopLogging" in blob
    ):
        parts.append(("fail", "auditor policy can reach workload data or delete controls"))
    seen_actions: set[str] = set()
    for statement in by_sid.values():
        _state, actions = actions_of(statement)
        if actions:
            seen_actions |= actions
    if seen_actions != AUDITOR_ACTIONS:
        parts.append(("fail", "auditor actions are not the assessed read set"))
    if any(part[0] != "pass" for part in parts):
        status, reason = combine([part for part in parts if part[0] != "pass"])
        return finding(rule_id, status, (role.address, policy.address), reason)
    return finding(
        rule_id,
        "pass",
        (role.address, policy.address),
        "auditor policy is read-only for the audit bucket and trail",
    )


def _actions_and_resource(
    statement: dict[str, object], actions: set[str], resources: set[str]
) -> tuple[str, str]:
    action_state, found_actions = actions_of(statement)
    resource_state, found_resources = resources_of(statement)
    if statement.get("Effect") != "Allow":
        return "fail", "statement effect is not Allow"
    if "unknown" in {action_state, resource_state}:
        return "unknown", "statement actions or resources are unknown"
    if found_actions != actions or found_resources != resources:
        return "fail", "statement actions or resources differ from the baseline"
    return "pass", "statement matches"


def _sole_service(principal: object, service: str) -> str:
    if not isinstance(principal, dict) or set(principal) != {"Service"}:
        return "fail"
    state, found = principal_services(principal)
    if state != "known":
        return "unknown"
    if found != {service}:
        return "fail"
    return "pass"


def _sole_aws(principal: object, expected: set[str]) -> str:
    if not isinstance(principal, dict) or set(principal) != {"AWS"}:
        return "fail"
    state, found = principals_aws(principal)
    if state != "known":
        return "unknown"
    if found != expected or "*" in found:
        return "fail"
    return "pass"


def _sse_header(
    component: str, bucket: Resource | None, active: list[Resource], scope: Scope
) -> Finding:
    rule_id = "S3-SSE-001"
    loaded = _policy_statements(component, bucket, active)
    if isinstance(loaded, Finding):
        return finding(rule_id, loaded.status, loaded.resource_addresses, loaded.reason)
    bucket, policy_resource, items = loaded
    by_sid, problem = _by_sid(items)
    if problem is not None:
        return finding(rule_id, problem[0], (bucket.address, policy_resource.address), problem[1])
    if not scope.complete:
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "encryption header deny cannot be checked without scope",
        )
    arn_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    if arn_state != "known" or bucket_arn is None:
        return finding(rule_id, "unknown", (bucket.address,), "bucket ARN is unknown")
    if component == "workload-data":
        return _workload_sse(bucket, policy_resource, by_sid, f"{bucket_arn}/*")
    return _audit_sse(bucket, policy_resource, by_sid, f"{bucket_arn}/*")


def _public_principal(principal: object) -> bool:
    return principal == "*" or _sole_aws(principal, {"*"}) == "pass"


def _put_object_shape(statement: dict[str, object], object_arn: str) -> str:
    if statement.get("Effect") != "Deny":
        return "fail"
    action_state, actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    if "unknown" in {action_state, resource_state}:
        return "unknown"
    if actions == {"s3:PutObject"} and resources == {object_arn}:
        return "pass"
    return "fail"


def _workload_sse(
    bucket: Resource,
    policy_resource: Resource,
    by_sid: dict[str, dict[str, object]],
    object_arn: str,
) -> Finding:
    rule_id = "S3-SSE-001"
    statement = by_sid.get("DenyIncorrectEncryptionHeader")
    if statement is None:
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "PutObject is not limited to an aws:kms encryption header",
        )
    shape = _put_object_shape(statement, object_arn)
    condition = statement.get("Condition")
    sse_state, sse = condition_values(
        statement, "StringNotEquals", "s3:x-amz-server-side-encryption"
    )
    strict = (
        isinstance(condition, dict)
        and set(condition) == {"StringNotEquals"}
        and set(condition["StringNotEquals"]) == {"s3:x-amz-server-side-encryption"}
        and sse_state == "known"
        and sse == {"aws:kms"}
    )
    if shape == "unknown" or sse_state == "unknown":
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "workload encryption header deny is partly unknown",
        )
    if shape == "pass" and _public_principal(statement.get("Principal")) and strict:
        return finding(
            rule_id,
            "pass",
            (bucket.address, policy_resource.address),
            "workload PutObject is denied unless the encryption header is aws:kms",
        )
    return finding(
        rule_id,
        "fail",
        (bucket.address, policy_resource.address),
        "workload encryption header deny is not limited to aws:kms",
    )


def _audit_sse(
    bucket: Resource,
    policy_resource: Resource,
    by_sid: dict[str, dict[str, object]],
    object_arn: str,
) -> Finding:
    rule_id = "S3-SSE-001"
    others = by_sid.get("DenyNonCloudTrailIncorrectEncryptionHeader")
    cloudtrail = by_sid.get("DenyCloudTrailIncorrectEncryptionHeader")
    if others is None or cloudtrail is None:
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "audit encryption header denies are incomplete",
        )
    other_shape = _put_object_shape(others, object_arn)
    trail_shape = _put_object_shape(cloudtrail, object_arn)
    other_condition = others.get("Condition")
    trail_condition = cloudtrail.get("Condition")
    if not isinstance(other_condition, dict) or set(other_condition) != {
        "StringNotEquals",
        "StringNotEqualsIfExists",
    }:
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "the non-CloudTrail deny does not use StringNotEqualsIfExists for the service name",
        )
    header_block = other_condition.get("StringNotEquals")
    service_block = other_condition.get("StringNotEqualsIfExists")
    if (
        not isinstance(header_block, dict)
        or not isinstance(service_block, dict)
        or set(header_block) != {"s3:x-amz-server-side-encryption"}
        or set(service_block) != {"aws:PrincipalServiceName"}
    ):
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "the non-CloudTrail deny condition keys do not match the baseline",
        )
    header_state, header = condition_values(
        others, "StringNotEquals", "s3:x-amz-server-side-encryption"
    )
    service_state, service = condition_values(
        others, "StringNotEqualsIfExists", "aws:PrincipalServiceName"
    )
    trail_state, trail_algs = condition_values(
        cloudtrail, "StringNotEquals", "s3:x-amz-server-side-encryption"
    )
    states = {other_shape, trail_shape, header_state, service_state, trail_state}
    if "unknown" in states:
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "audit encryption header denies are partly unknown",
        )
    others_ok = (
        other_shape == "pass"
        and _public_principal(others.get("Principal"))
        and header == {"aws:kms"}
        and service == {"cloudtrail.amazonaws.com"}
    )
    trail_ok = (
        trail_shape == "pass"
        and _sole_service(cloudtrail.get("Principal"), "cloudtrail.amazonaws.com") == "pass"
        and isinstance(trail_condition, dict)
        and set(trail_condition) == {"StringNotEquals"}
        and set(trail_condition["StringNotEquals"]) == {"s3:x-amz-server-side-encryption"}
        and trail_algs == {"AES256", "aws:kms"}
    )
    if others_ok and trail_ok:
        return finding(
            rule_id,
            "pass",
            (bucket.address, policy_resource.address),
            "callers other than CloudTrail are limited to aws:kms, and CloudTrail may send aws:kms or AES256",
        )
    return finding(
        rule_id,
        "fail",
        (bucket.address, policy_resource.address),
        "audit encryption header denies do not match the CloudTrail aws:kms or AES256 allowance",
    )


def _audit_delete(inventory: Inventory, active: list[Resource], scope: Scope) -> Finding:
    rule_id = "S3-AUDIT-DEL-001"
    bucket = inventory.one("aws_s3_bucket", "audit-logs")
    loaded = _policy_statements("audit-logs", bucket, active)
    if isinstance(loaded, Finding):
        return finding(rule_id, loaded.status, loaded.resource_addresses, loaded.reason)
    bucket, policy_resource, items = loaded
    by_sid, problem = _by_sid(items)
    if problem is not None:
        return finding(rule_id, problem[0], (bucket.address, policy_resource.address), problem[1])
    statement = by_sid.get("DenyAuditObjectDelete")
    if statement is None:
        return finding(
            rule_id,
            "fail",
            (bucket.address, policy_resource.address),
            "audit object delete is not denied",
        )
    if not scope.complete:
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "audit delete deny cannot be checked without scope",
        )
    arn_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    if arn_state != "known" or bucket_arn is None:
        return finding(rule_id, "unknown", (bucket.address,), "audit bucket ARN is unknown")
    action_state, actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    if "unknown" in {action_state, resource_state}:
        return finding(
            rule_id,
            "unknown",
            (bucket.address, policy_resource.address),
            "audit delete deny is partly unknown",
        )
    condition = statement.get("Condition")
    if (
        statement.get("Effect") == "Deny"
        and _public_principal(statement.get("Principal"))
        and actions == {"s3:DeleteObject", "s3:DeleteObjectVersion"}
        and resources == {f"{bucket_arn}/*"}
        and condition in (None, {})
    ):
        return finding(
            rule_id,
            "pass",
            (bucket.address, policy_resource.address),
            "audit object and version deletes are denied for every principal, with no break-glass condition",
        )
    return finding(
        rule_id,
        "fail",
        (bucket.address, policy_resource.address),
        "audit delete deny is missing an action, is not a deny, or exempts a principal",
    )


def _root_statement(statement: dict[str, object], scope: Scope) -> tuple[str, str]:
    root = f"arn:{scope.partition}:iam::{scope.account}:root"
    sole = _sole_aws(statement.get("Principal"), {root})
    if sole == "unknown":
        return "unknown", "root principal is partly unknown"
    if sole == "fail":
        return "fail", "root key statement is not limited to this account"
    principal_state, principals = principals_aws(statement.get("Principal"))
    action_state, actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    if "unknown" in {principal_state, action_state, resource_state}:
        return "unknown", "root key statement is partly unknown"
    if (
        statement.get("Effect") == "Allow"
        and principals == {root}
        and actions == {"kms:*"}
        and resources == {"*"}
        and "Condition" not in statement
    ):
        return "pass", "root administration is this account only"
    return "fail", "root key statement is not limited to this account"


def _workload_key_use(
    statement: dict[str, object], inventory: Inventory, scope: Scope
) -> tuple[str, str]:
    role = inventory.one("aws_iam_role", "workload-operator")
    bucket = inventory.one("aws_s3_bucket", "workload-data")
    if role is None or bucket is None or not scope.complete:
        return "unknown", "workload key grant is missing a role or bucket"
    role_state, role_arn = _role_arn(role, scope)
    bucket_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    if role_state != "known" or bucket_state != "known" or role_arn is None or bucket_arn is None:
        return "unknown", "workload role or bucket ARN is unknown"
    sole = _sole_aws(statement.get("Principal"), {role_arn})
    if sole == "unknown":
        return "unknown", "workload key principal is partly unknown"
    if sole == "fail":
        return "fail", "workload key principal includes an unexpected identity"
    principal_state, principals = principals_aws(statement.get("Principal"))
    action_state, actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    via_state, via = condition_values(statement, "StringEquals", "kms:ViaService")
    context_state, context = condition_values(
        statement, "StringEquals", "kms:EncryptionContext:aws:s3:arn"
    )
    if "unknown" in {principal_state, action_state, resource_state, via_state, context_state}:
        return "unknown", "workload key grant is partly unknown"
    if (
        statement.get("Effect") == "Allow"
        and principals == {role_arn}
        and actions == _WORKLOAD_KEY_ACTIONS
        and resources == {"*"}
        and via == {f"s3.{scope.region}.amazonaws.com"}
        and context == {bucket_arn}
    ):
        return "pass", "workload role can use the key for this bucket"
    return "fail", "workload key grant does not match the baseline"


def _cloudtrail_encrypt(statement: dict[str, object], scope: Scope) -> tuple[str, str]:
    base = _service_statement(statement, {"kms:GenerateDataKey*"}, scope.trail_arn)
    if base[0] != "pass":
        return base
    state, values = condition_values(
        statement, "StringLike", "kms:EncryptionContext:aws:cloudtrail:arn"
    )
    expected = {f"arn:{scope.partition}:cloudtrail:*:{scope.account}:trail/*"}
    if state == "known" and values == expected:
        return "pass", "CloudTrail encrypt grant is source restricted"
    if state == "unknown":
        return "unknown", "CloudTrail encryption context is unknown"
    return "fail", "CloudTrail encrypt grant encryption context does not match"


def _cloudtrail_describe(statement: dict[str, object], scope: Scope) -> tuple[str, str]:
    return _service_statement(statement, {"kms:DescribeKey"}, scope.trail_arn)


def _cloudtrail_decrypt(statement: dict[str, object]) -> tuple[str, str]:
    sole = _sole_service(statement.get("Principal"), "cloudtrail.amazonaws.com")
    if sole == "fail":
        return "fail", "CloudTrail decrypt principal includes an unexpected identity"
    if sole == "unknown":
        return "unknown", "CloudTrail decrypt principal is partly unknown"
    principal_state, services = principal_services(statement.get("Principal"))
    action_state, actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    if "unknown" in {principal_state, action_state, resource_state}:
        return "unknown", "CloudTrail decrypt grant is partly unknown"
    if statement.get("Effect") != "Allow":
        return "fail", "CloudTrail decrypt grant effect is not Allow"
    if (
        services == {"cloudtrail.amazonaws.com"}
        and actions == {"kms:Decrypt"}
        and resources == {"*"}
        and "Condition" not in statement
    ):
        return "pass", "CloudTrail decrypt grant matches the documented statement without SourceArn"
    return "fail", "CloudTrail decrypt grant does not match the documented statement"


def _auditor_decrypt(
    statement: dict[str, object], inventory: Inventory, scope: Scope
) -> tuple[str, str]:
    role = inventory.one("aws_iam_role", "auditor")
    if role is None:
        return "fail", "auditor role is absent"
    role_state, role_arn = _role_arn(role, scope)
    if role_state != "known" or role_arn is None:
        return "unknown", "auditor role ARN is unknown"
    sole = _sole_aws(statement.get("Principal"), {role_arn})
    if sole == "unknown":
        return "unknown", "auditor decrypt principal is partly unknown"
    if sole == "fail":
        return "fail", "auditor decrypt principal includes an unexpected identity"
    principal_state, principals = principals_aws(statement.get("Principal"))
    action_state, actions = actions_of(statement)
    state, values = condition_values(statement, "Null", "kms:EncryptionContext:aws:cloudtrail:arn")
    via_state, via = condition_values(statement, "StringEquals", "kms:ViaService")
    if "unknown" in {principal_state, action_state, state, via_state}:
        return "unknown", "auditor decrypt grant is partly unknown"
    if statement.get("Effect") != "Allow":
        return "fail", "auditor decrypt grant effect is not Allow"
    if (
        principals == {role_arn}
        and actions == {"kms:Decrypt"}
        and values == {"false"}
        and via == {f"s3.{scope.region}.amazonaws.com"}
    ):
        return "pass", "auditor can decrypt CloudTrail objects through S3 only"
    return "fail", "auditor decrypt grant does not match the baseline"


def _service_statement(
    statement: dict[str, object], actions: set[str], trail_arn: str | None
) -> tuple[str, str]:
    if trail_arn is None:
        return "unknown", "trail ARN is unknown"
    sole = _sole_service(statement.get("Principal"), "cloudtrail.amazonaws.com")
    if sole == "fail":
        return "fail", "CloudTrail principal includes an unexpected identity"
    if sole == "unknown":
        return "unknown", "CloudTrail principal is partly unknown"
    principal_state, services = principal_services(statement.get("Principal"))
    action_state, found_actions = actions_of(statement)
    resource_state, resources = resources_of(statement)
    source_state, source = condition_values(statement, "StringEquals", "aws:SourceArn")
    if "unknown" in {principal_state, action_state, resource_state, source_state}:
        return "unknown", "CloudTrail key statement is partly unknown"
    if (
        statement.get("Effect") == "Allow"
        and services == {"cloudtrail.amazonaws.com"}
        and found_actions == actions
        and resources == {"*"}
        and source == {trail_arn}
    ):
        return "pass", "CloudTrail key statement matches"
    return "fail", "CloudTrail key statement does not match"


def _expect_statement(
    statement: dict[str, object],
    *,
    service: str,
    actions: set[str],
    resources: set[str],
    source: str,
    acl: str | None = None,
) -> tuple[str, str]:
    sole = _sole_service(statement.get("Principal"), service)
    if sole == "fail":
        return "fail", "CloudTrail bucket principal includes an unexpected identity"
    if sole == "unknown":
        return "unknown", "CloudTrail bucket principal is partly unknown"
    principal_state, services = principal_services(statement.get("Principal"))
    action_state, found_actions = actions_of(statement)
    resource_state, found_resources = resources_of(statement)
    source_state, found_source = condition_values(statement, "StringEquals", "aws:SourceArn")
    checks = [principal_state, action_state, resource_state, source_state]
    acl_values: set[str] = set()
    if acl is not None:
        acl_state, acl_values = condition_values(statement, "StringEquals", "s3:x-amz-acl")
        checks.append(acl_state)
    else:
        acl_state = "known"
    if "unknown" in checks:
        return "unknown", "CloudTrail bucket statement is partly unknown"
    if (
        statement.get("Effect") == "Allow"
        and services == {service}
        and found_actions == actions
        and found_resources == resources
        and found_source == {source}
        and (acl is None or acl_values == {acl})
    ):
        return "pass", "CloudTrail bucket statement matches"
    return "fail", "CloudTrail bucket statement does not match"


def _scope(active: list[Resource], inventory: Inventory) -> Scope:
    scope = Scope()
    trail = inventory.one("aws_cloudtrail", "audit-logs")
    trail_name = None
    if trail is not None:
        state, value = attr(trail, ("name",))
        if state == "known" and isinstance(value, str):
            trail_name = value
    for resource in active:
        for policy_field in ("policy", "assume_role_policy"):
            state, raw = attr(resource, (policy_field,))
            if state == "known":
                _collect_policy_scope(raw, scope, trail_name)
        if resource.type_name == "aws_iam_role_policy":
            state, raw = attr(resource, ("policy",))
            if state == "known":
                _collect_policy_scope(raw, scope, trail_name)
    return scope


def _collect_policy_scope(raw: object, scope: Scope, trail_name: str | None) -> None:
    state, parsed = parse_policy(raw)
    if state != "known" or parsed is None:
        return
    values: list[str] = []
    _walk_strings(parsed, values)
    for value in values:
        if value.startswith("arn:"):
            parts = value.split(":", 5)
            if len(parts) >= 6:
                partition, region, account = parts[1], parts[3], parts[4]
                if re.fullmatch(r"[a-z0-9-]+", partition):
                    scope.partitions.add(partition)
                if _REGION.fullmatch(region):
                    scope.regions.add(region)
                if _ACCOUNT.fullmatch(account):
                    scope.accounts.add(account)
                if (
                    trail_name is not None
                    and parts[2] == "cloudtrail"
                    and value.endswith(f":trail/{trail_name}")
                    and "*" not in value
                ):
                    scope.trail_arns.add(value)
        matched = re.search(r"/AWSLogs/([0-9]{12})/", value)
        if matched:
            scope.accounts.add(matched.group(1))


def _walk_strings(node: object, found: list[str]) -> None:
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            _walk_strings(value, found)
    elif isinstance(node, list):
        for value in node:
            _walk_strings(value, found)


def _bucket_policy(
    component: str, bucket: Resource | None, active: list[Resource], scope: Scope
) -> Finding | tuple[Resource, dict[str, object], str]:
    loaded = _policy_statements(component, bucket, active)
    if isinstance(loaded, Finding):
        return loaded
    bucket, policy_resource, _items = loaded
    state, raw = attr(policy_resource, ("policy",))
    parsed_state, parsed = parse_policy(raw) if state == "known" else ("unknown", None)
    if parsed_state != "known" or parsed is None or not scope.complete:
        return finding(
            "S3-TLS-001",
            "unknown",
            (bucket.address, policy_resource.address),
            "bucket policy or scope is not fully known",
        )
    arn_state, bucket_arn = _resource_arn(bucket, scope, "s3")
    if arn_state != "known" or bucket_arn is None:
        return finding("S3-TLS-001", "unknown", (bucket.address,), "bucket ARN is unknown")
    return policy_resource, parsed, bucket_arn


def _policy_statements(
    component: str, bucket: Resource | None, active: list[Resource]
) -> Finding | tuple[Resource, Resource, list[dict[str, object]]]:
    if bucket is None:
        return _missing("S3-POLICY-001", component, f"{component} bucket is absent")
    matched, unresolved = _children(active, bucket, "aws_s3_bucket_policy")
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        return finding(
            "S3-POLICY-001", status, (bucket.address,), "bucket policy is missing or not linked"
        )
    state, raw = attr(matched[0], ("policy",))
    if state == "unknown":
        return finding(
            "S3-POLICY-001",
            "unknown",
            (bucket.address, matched[0].address),
            "bucket policy is unknown",
        )
    if state != "known":
        return finding(
            "S3-POLICY-001", "fail", (bucket.address, matched[0].address), "bucket policy is absent"
        )
    parsed_state, parsed = parse_policy(raw)
    if parsed_state != "known" or parsed is None:
        return finding(
            "S3-POLICY-001",
            "unknown",
            (bucket.address, matched[0].address),
            "bucket policy is not assessable JSON",
        )
    statement_state, items = statements(parsed)
    if statement_state != "known" or items is None:
        return finding(
            "S3-POLICY-001",
            "unknown",
            (bucket.address, matched[0].address),
            "bucket policy statements are not assessable",
        )
    return bucket, matched[0], items


def _children(
    active: list[Resource], bucket: Resource, type_name: str
) -> tuple[list[Resource], bool]:
    names = _bucket_name_set(bucket)
    matched: list[Resource] = []
    unresolved = False
    if not names:
        return [], True
    for resource in active:
        if resource.type_name != type_name:
            continue
        state, value = attr(resource, ("bucket",))
        if state == "known" and value in names:
            matched.append(resource)
        elif state != "known":
            unresolved = True
    return matched, unresolved


def _bucket_name_set(bucket: Resource) -> set[str]:
    return _known_strings(bucket, ("bucket", "id"))


def _known_strings(resource: Resource, names: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    for name in names:
        state, value = attr(resource, (name,))
        if state == "known" and isinstance(value, str) and value:
            found.add(value)
    return found


def _key_ids(key: Resource) -> set[str]:
    return _known_strings(key, ("arn", "id", "key_id"))


def _alias_for(
    inventory: Inventory, active: list[Resource], component: str
) -> tuple[str, Resource | None]:
    key = inventory.one("aws_kms_key", component)
    if key is None:
        return "absent", None
    ids = _key_ids(key)
    aliases = [resource for resource in active if resource.type_name == "aws_kms_alias"]
    if not ids:
        if any(attr(resource, ("target_key_id",))[0] == "unknown" for resource in aliases):
            return "unknown", None
        return "absent", None
    matched = []
    unknown = False
    for alias in aliases:
        state, target = attr(alias, ("target_key_id",))
        if state == "unknown":
            unknown = True
        elif state == "known" and target in ids:
            matched.append(alias)
    if len(matched) == 1 and not unknown:
        return "known", matched[0]
    if unknown:
        return "unknown", matched[0] if len(matched) == 1 else None
    if len(matched) == 1:
        return "known", matched[0]
    return "absent", None


def _alias_id_matches(alias: Resource, key_id: str, scope: Scope) -> bool:
    state, arn = attr(alias, ("arn",))
    if state == "known" and arn == key_id:
        return True
    name_state, name = attr(alias, ("name",))
    if (
        name_state == "known"
        and isinstance(name, str)
        and scope.complete
        and key_id == f"arn:{scope.partition}:kms:{scope.region}:{scope.account}:{name}"
    ):
        return True
    return False


def _resource_arn(resource: Resource, scope: Scope, service: str) -> tuple[str, str | None]:
    state, value = attr(resource, ("arn",))
    if state == "known" and isinstance(value, str):
        return "known", value
    if service == "s3":
        names = _bucket_name_set(resource)
        if len(names) == 1 and scope.partition:
            return "known", f"arn:{scope.partition}:s3:::{next(iter(names))}"
    return ("unknown", None) if state == "unknown" else ("absent", None)


def _role_arn(role: Resource, scope: Scope) -> tuple[str, str | None]:
    state, value = attr(role, ("arn",))
    if state == "known" and isinstance(value, str):
        return "known", value
    name_state, name = attr(role, ("name",))
    if name_state == "known" and isinstance(name, str) and scope.complete:
        return "known", f"arn:{scope.partition}:iam::{scope.account}:role/{name}"
    if state == "unknown" or name_state == "unknown":
        return "unknown", None
    return "absent", None


def _flex(resource: Resource, prefix: tuple[Any, ...], key: str) -> tuple[str, object]:
    state, value = attr(resource, prefix + (key,))
    if state != "absent":
        return state, value
    if prefix and isinstance(prefix[-1], int):
        return attr(resource, prefix[:-1] + (key,))
    return state, value


def _without_index(path: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(part for part in path if not isinstance(part, int))


def _by_sid(
    items: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], tuple[str, str] | None]:
    found: dict[str, dict[str, object]] = {}
    for item in items:
        sid = item.get("Sid")
        if not isinstance(sid, str):
            return {}, ("unknown", "a statement has no Sid")
        if sid in found:
            return {}, ("fail", f"statement id {sid} is duplicated")
        found[sid] = item
    return found, None


def _account_bpa(active: list[Resource], scope: Scope) -> Finding:
    rule_id = "S3-ACCT-BPA-001"
    blocks = [item for item in active if item.type_name == "aws_s3_account_public_access_block"]
    if not blocks:
        return finding(
            rule_id,
            "fail",
            ("missing:aws_s3_account_public_access_block",),
            "the plan does not set account-level S3 Block Public Access",
        )
    addresses = tuple(item.address for item in blocks)
    if len(blocks) != 1:
        return finding(
            rule_id,
            "fail",
            addresses,
            "more than one account-level public access block is planned for the account",
        )
    block = blocks[0]
    parts: list[tuple[str, str]] = []
    state, account_id = attr(block, ("account_id",))
    if state == "unknown" or scope.account is None:
        parts.append(("unknown", "account_id or plan account is unknown"))
    elif state != "known" or account_id != scope.account:
        parts.append(("fail", "account_id is not explicitly this plan's account"))
    for flag in _BPA:
        flag_state, value = attr(block, (flag,))
        if flag_state == "known" and value is True:
            continue
        if flag_state == "unknown":
            parts.append(("unknown", f"{flag} is unknown"))
        elif flag_state == "absent":
            parts.append(("fail", f"{flag} is absent"))
        else:
            parts.append(("fail", f"{flag} is {shown(value)}"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, addresses, reason)
    return finding(
        rule_id,
        "pass",
        addresses,
        "account-level Block Public Access is planned with all four settings true; an organization policy is not assessed",
    )


def _retention(bucket: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "S3-RET-001"
    if bucket is None:
        return _missing(rule_id, "audit-logs", "audit-logs bucket is absent")
    matched, unresolved = _children(active, bucket, "aws_s3_bucket_lifecycle_configuration")
    if len(matched) != 1 or unresolved:
        status = "unknown" if unresolved and len(matched) == 0 else "fail"
        return finding(
            rule_id,
            status,
            (bucket.address,),
            "audit lifecycle configuration is missing or not linked",
        )
    lifecycle = matched[0]
    addresses = (bucket.address, lifecycle.address)
    state, rules = attr(lifecycle, ("rule",))
    if state == "unknown":
        return finding(rule_id, "unknown", addresses, "audit lifecycle rules are unknown")
    if state != "known" or not isinstance(rules, list):
        return finding(rule_id, "fail", addresses, "audit lifecycle rules are absent")
    floor = AUDIT_RETENTION_FLOOR_DAYS
    parts: list[tuple[str, str]] = []
    current: list[int] = []
    noncurrent: list[int] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            parts.append(("unknown", "a lifecycle rule is not an object"))
            continue
        status_state, status = attr(lifecycle, ("rule", index, "status"))
        if status_state == "unknown":
            parts.append(("unknown", "a lifecycle rule status is unknown"))
            continue
        if status != "Enabled":
            continue
        for block, key, sink, label in (
            ("expiration", "days", current, "current-version expiration"),
            (
                "noncurrent_version_expiration",
                "noncurrent_days",
                noncurrent,
                "noncurrent expiration",
            ),
        ):
            block_state, items = attr(lifecycle, ("rule", index, block))
            if block_state == "unknown":
                parts.append(("unknown", f"{label} is unknown"))
                continue
            if block_state != "known" or items in (None, []):
                continue
            if not isinstance(items, list):
                parts.append(("unknown", f"{label} is not a list"))
                continue
            for item_index in range(len(items)):
                path = ("rule", index, block, item_index)
                value_state, value = attr(lifecycle, path + (key,))
                if value_state == "unknown":
                    parts.append(("unknown", f"{label} days are unknown"))
                elif isinstance(value, int) and not isinstance(value, bool):
                    sink.append(value)
                    if value < floor:
                        parts.append(("fail", f"{label} of {value} days is below {floor} days"))
                if block == "expiration":
                    date_state, date = attr(lifecycle, path + ("date",))
                    if date_state == "unknown":
                        parts.append(("unknown", "expiration date is unknown"))
                    elif date_state == "known" and date not in (None, ""):
                        parts.append(
                            ("fail", "an expiration by date is not checked against retention")
                        )
    if current and noncurrent and min(noncurrent) < min(current):
        parts.append(
            ("fail", "noncurrent versions are kept for fewer days than current log objects")
        )
    noncurrent_unknown = any(
        status == "unknown" and "noncurrent" in reason for status, reason in parts
    )
    if current and not noncurrent and not noncurrent_unknown:
        parts.append(
            ("fail", "current log objects expire but noncurrent versions have no stated retention")
        )
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, addresses, reason)
    return finding(
        rule_id,
        "pass",
        addresses,
        f"no enabled audit lifecycle rule removes a log version before {floor} days; lifecycle is not WORM and can be edited",
    )


def _key_scope(component: str, key: Resource | None, scope: Scope) -> Finding:
    rule_id = "KMS-SCOPE-001"
    if key is None:
        return _missing(rule_id, component, f"{component} key is absent")
    state, raw = attr(key, ("policy",))
    if state == "unknown":
        return finding(rule_id, "unknown", (key.address,), "key policy is unknown")
    if state != "known":
        return finding(rule_id, "fail", (key.address,), "key policy is absent")
    parsed_state, parsed = parse_policy(raw)
    statement_state, items = statements(parsed) if parsed else ("unknown", None)
    if parsed_state != "known" or statement_state != "known" or items is None:
        return finding(rule_id, "unknown", (key.address,), "key policy is not assessable")
    if not scope.complete:
        return finding(rule_id, "unknown", (key.address,), "account scope is unknown")
    root = f"arn:{scope.partition}:iam::{scope.account}:root"
    parts: list[tuple[str, str]] = []
    for statement in items:
        if statement.get("Effect") != "Allow":
            continue
        sid = statement.get("Sid", "?")
        principal = statement.get("Principal")
        aws_state, aws = principals_aws(principal)
        service_state, services = principal_services(principal)
        action_state, actions = actions_of(statement)
        if "unknown" in {aws_state, service_state, action_state}:
            parts.append(("unknown", f"statement {sid} is partly unknown"))
            continue
        if aws == {root} and service_state == "absent":
            continue
        if "*" in aws or "*" in services or (isinstance(principal, dict) and "*" in principal):
            parts.append(("fail", f"statement {sid} allows a wildcard principal"))
            continue
        extra = sorted(action for action in actions if action not in KEY_USE_ACTIONS)
        if extra:
            parts.append(("fail", f"statement {sid} grants {', '.join(extra[:3])}"))
            continue
        if not statement.get("Condition"):
            documented = (
                services == {"cloudtrail.amazonaws.com"}
                and aws_state == "absent"
                and actions == {"kms:Decrypt"}
            )
            if not documented:
                parts.append(("fail", f"statement {sid} has no condition"))
    if parts:
        status, reason = combine(parts)
        return finding(rule_id, status, (key.address,), reason)
    return finding(
        rule_id,
        "pass",
        (key.address,),
        "non-root key grants are key-use only and conditioned, except the documented CloudTrail decrypt statement; account-root kms:* still delegates to IAM",
    )


def _tamper(component: str, role: Resource | None, active: list[Resource]) -> Finding:
    rule_id = "IAM-TAMPER-001"
    if role is None:
        return _missing(rule_id, component, f"{component} role is absent")
    names = _known_strings(role, ("name", "id"))
    policies: list[Resource] = []
    for policy in active:
        if policy.type_name != "aws_iam_role_policy":
            continue
        state, role_name = attr(policy, ("role",))
        if state == "unknown":
            return finding(rule_id, "unknown", (role.address,), "inline policy role is unknown")
        if state == "known" and role_name in names:
            policies.append(policy)
    addresses = (role.address, *(item.address for item in policies))
    hits: set[str] = set()
    for policy in policies:
        state, raw = attr(policy, ("policy",))
        parsed_state, parsed = parse_policy(raw) if state == "known" else ("unknown", None)
        statement_state, items = statements(parsed) if parsed else ("unknown", None)
        if parsed_state != "known" or statement_state != "known" or items is None:
            return finding(rule_id, "unknown", addresses, "an inline policy is not assessable")
        for statement in items:
            if statement.get("Effect") != "Allow":
                continue
            action_state, actions = actions_of(statement)
            if action_state == "unknown":
                return finding(rule_id, "unknown", addresses, "inline policy actions are unknown")
            for pattern in actions:
                for action in TAMPER_ACTIONS:
                    if fnmatch.fnmatchcase(action.lower(), pattern.lower()):
                        hits.add(action)
    if hits:
        shown_hits = ", ".join(sorted(hits)[:4])
        return finding(
            rule_id, "fail", addresses, f"inline policy allows tamper actions: {shown_hits}"
        )
    return finding(
        rule_id,
        "pass",
        addresses,
        "inline policies allow no trail, bucket policy, lifecycle, lock, or key administration action; other IAM in the account is not visible",
    )
