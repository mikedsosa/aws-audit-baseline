"""Explicit rule ids and the controls this checker does not assess."""

from __future__ import annotations

RULESET_ID = "aws-private-audit-baseline"
RULESET_VERSION = "0.1.0"
EVIDENCE_SCHEMA_VERSION = "1.0.0"

# Resource types the checker is willing to classify. Anything else is unknown,
# which keeps an unrelated resource from disappearing into a pass.
SUPPORTED_TYPES = frozenset(
    {
        "aws_cloudtrail",
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_kms_alias",
        "aws_kms_key",
        "aws_s3_account_public_access_block",
        "aws_s3_bucket",
        "aws_s3_bucket_lifecycle_configuration",
        "aws_s3_bucket_object_lock_configuration",
        "aws_s3_bucket_ownership_controls",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_versioning",
    }
)

BUCKET_COMPONENTS = ("workload-data", "audit-logs")
KEY_COMPONENTS = ("workload-data", "audit-logs")
ROLE_COMPONENTS = ("workload-operator", "auditor")

DEPLOYMENT_STATUS = "not-deployed-by-this-draft"

# CloudTrail read APIs that this baseline allows on Resource "*".
# Resource-level support for these three was not re-checked against the
# Service Authorization Reference in this draft. Any other action on "*" fails.
ACCOUNT_SCOPED_TRAIL_READS = frozenset(
    {
        "cloudtrail:DescribeTrails",
        "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents",
    }
)

WORKLOAD_ACTIONS = frozenset(
    {
        "s3:AbortMultipartUpload",
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
    }
)

AUDITOR_ACTIONS = frozenset(
    {
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions",
    }
)

# Stated minimum retention for CloudTrail log objects and their noncurrent
# versions. Matches the audit_log_retention_days lower bound in variables.tf.
AUDIT_RETENTION_FLOOR_DAYS = 365

OBJECT_LOCK_MODES = frozenset({"COMPLIANCE", "GOVERNANCE"})

# Actions that could stop, redirect, or erase the audit trail or its keys.
# No baseline role may be allowed any of these, directly or through a wildcard.
TAMPER_ACTIONS = frozenset(
    {
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "kms:CreateGrant",
        "kms:DisableKey",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "s3:BypassGovernanceRetention",
        "s3:DeleteBucketPolicy",
        "s3:PutAccountPublicAccessBlock",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration",
        "s3:PutObjectRetention",
    }
)

# Key policy actions a non-root statement may grant. Anything else, including
# kms:Encrypt, kms:ReEncrypt*, kms:CreateGrant, or an admin action, fails
# KMS-SCOPE-001.
KEY_USE_ACTIONS = frozenset(
    {
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:GenerateDataKey",
        "kms:GenerateDataKey*",
    }
)

RULES: tuple[tuple[str, str], ...] = (
    (
        "BASE-COMP-001",
        "The plan's end state has exactly the baseline components, each tagged once.",
    ),
    (
        "BASE-SCOPE-001",
        "Known account, Region, and partition values in the plan agree with each other.",
    ),
    (
        "DISCLAIM-001",
        "The plan output deployment_status is the draft disclaimer string.",
    ),
    (
        "PROV-001",
        "The plan configuration contains no provisioners. This tool does not execute them.",
    ),
    (
        "UNSUPPORTED-TYPE-001",
        "Every resource_changes entry is a supported type. Other types are unknown, not a pass.",
    ),
    (
        "S3-BPA-001",
        "Each bucket has one public access block and all four settings are true.",
    ),
    (
        "S3-ACCT-BPA-001",
        "The plan sets account-level S3 Block Public Access for this account with all four settings true.",
    ),
    (
        "S3-ENC-001",
        "Each bucket default encryption is SSE-KMS with a bucket key, bound to that component's alias.",
    ),
    (
        "S3-SSE-001",
        "The workload bucket denies PutObject unless the header is aws:kms. The audit bucket does the same for other callers, using StringNotEqualsIfExists so an IAM caller cannot send AES256. CloudTrail may send aws:kms or AES256.",
    ),
    (
        "S3-AUDIT-DEL-001",
        "The audit bucket denies s3:DeleteObject and s3:DeleteObjectVersion for every principal, with no break-glass condition.",
    ),
    (
        "S3-VER-001",
        "Each bucket has versioning status Enabled.",
    ),
    (
        "S3-OWN-001",
        "Each bucket ownership control is BucketOwnerEnforced.",
    ),
    (
        "S3-TLS-001",
        "Each bucket policy denies s3:* when aws:SecureTransport is false.",
    ),
    (
        "S3-POLICY-001",
        "Bucket policy statement IDs are exactly the set this baseline assesses.",
    ),
    (
        "S3-DESTROY-001",
        "force_destroy is explicitly false on each bucket.",
    ),
    (
        "S3-LOCK-001",
        "Workload Object Lock is explicitly off. The audit bucket either has Object Lock explicitly off, which is not an immutability claim, or has it on with a GOVERNANCE or COMPLIANCE default retention of at least the retention floor.",
    ),
    (
        "S3-LIFE-001",
        "Lifecycle aborts incomplete uploads, expires audit objects on the baseline window, and does not expire current workload objects.",
    ),
    (
        "S3-RET-001",
        "No enabled audit lifecycle rule can delete a current or noncurrent log version before the stated retention floor, and noncurrent versions are kept at least as long as current ones.",
    ),
    (
        "KMS-ROT-001",
        "Each customer managed key enables rotation with a 365 day period.",
    ),
    (
        "KMS-WIN-001",
        "Each customer managed key has a 30 day deletion window.",
    ),
    (
        "KMS-SPEC-001",
        "Each key is an enabled single-Region symmetric encryption key.",
    ),
    (
        "KMS-POL-001",
        "Key policies match the baseline statements: account root, workload use, CloudTrail, and auditor decrypt.",
    ),
    (
        "KMS-SCOPE-001",
        "Outside the account-root statement, key policy allows grant only key-use actions, never to a wildcard principal, and always with a condition.",
    ),
    (
        "KMS-ALIAS-001",
        "Each component key has one alias whose target is that key.",
    ),
    (
        "KMS-SEP-001",
        "The workload and audit buckets do not use the same KMS alias or key.",
    ),
    (
        "CT-FLAG-001",
        "The trail explicitly enables logging, validation, global events, and multi-Region delivery, and it is not an organization trail.",
    ),
    (
        "CT-DEST-001",
        "The trail writes to the audit bucket and audit alias under the cloudtrail prefix.",
    ),
    (
        "CT-S3POL-001",
        "The audit bucket policy grants CloudTrail GetBucketAcl and PutObject only with the trail source ARN and the bucket-owner-full-control ACL.",
    ),
    (
        "CT-DATA-001",
        "Management events are explicit, and the only data resource is S3 object events for the workload bucket. The audit bucket is not a data resource. Advanced and Insights selectors are empty.",
    ),
    (
        "IAM-TRUST-001",
        "Each role trusts only IAM users in this account and requires MFA on AssumeRole.",
    ),
    (
        "IAM-PERM-001",
        "Inline role policies stay inside the workload prefix and the auditor read set.",
    ),
    (
        "IAM-TAMPER-001",
        "No baseline role inline policy allows an action that could stop the trail, change its selectors, rewrite bucket or key policy, shorten retention, or schedule key deletion.",
    ),
    (
        "IAM-SESSION-001",
        "Each role max_session_duration is 3600 seconds or less.",
    ),
)

NOT_ASSESSED: tuple[tuple[str, str], ...] = (
    (
        "organization-public-access-block",
        "The plan can set account-level Block Public Access. It does not set or prove an AWS Organizations S3 policy.",
    ),
    (
        "organization-trail-scope",
        "The trail is a single-account trail. An organization trail must be created from the management account or a delegated administrator and is not modeled here.",
    ),
    (
        "organization-scps-rcps-permission-boundaries",
        "This plan is not an AWS Organizations policy and does not show SCPs, RCPs, or permission boundaries.",
    ),
    (
        "s3-object-lock-default-off-and-mfa-delete",
        "Object Lock on the audit bucket is opt-in and off in the example plan. MFA Delete is not enabled; the CloudTrail best-practices page says it cannot be used with lifecycle configurations.",
    ),
    (
        "s3-server-access-logging",
        "S3 server access logging is not configured. CloudTrail management events are not object access logs.",
    ),
    (
        "cloudtrail-data-events-other-resources",
        "Data events are selected for workload bucket objects only. Other buckets, Lambda, DynamoDB, and other data event types are not logged.",
    ),
    (
        "cloudtrail-insights-lake-cloudwatch-eventbridge",
        "CloudTrail Insights, Lake, CloudWatch Logs delivery, and EventBridge are not part of this stack.",
    ),
    (
        "cloudtrail-digest-validation-execution",
        "The checker can see enable_log_file_validation only. It does not download or validate digest files.",
    ),
    (
        "cloudtrail-recursive-logging",
        "recursive_logging is not set. AWS provider 5.100.0 has no such argument. The CreateTrail API default is true and was not overridden.",
    ),
    (
        "guardduty-securityhub-config-analyzer-macie",
        "GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and Macie are not deployed or queried. An account allows one account-level analyzer per type per Region, so this stack does not create one.",
    ),
    (
        "network-controls",
        "No VPC, endpoint, security group, or private network is in this stack. CloudTrail delivery is not forced through a VPC endpoint.",
    ),
    (
        "sse-c-block-setting",
        "The April 2026 S3 SSE-C default is not configured or verified by this Terraform.",
    ),
    (
        "other-iam-in-the-account",
        "Account-root kms:* delegates key administration to IAM. Other IAM policies in the account are invisible here.",
    ),
    (
        "audit-bucket-overwrite-by-iam",
        "The audit bucket policy does not deny PutObject from IAM callers that send aws:kms. An overwrite keeps the old version as noncurrent for the retention period but is not blocked.",
    ),
    (
        "cloudtrail-kms-decrypt-source-arn",
        "The CloudTrail kms:Decrypt statement follows the published example and is not restricted by aws:SourceArn.",
    ),
    (
        "runtime-aws-api-state",
        "A plan JSON file is not a description of a live account. This tool does not call AWS.",
    ),
    (
        "shared-global-bucket-namespace",
        "Bucket names are in the shared global namespace. This draft does not use an account regional namespace.",
    ),
)

CERTIFICATION_SENTENCE = (
    "This output is not a compliance certification and does not claim complete coverage."
)
