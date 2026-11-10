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
        "aws_s3_bucket",
        "aws_s3_bucket_lifecycle_configuration",
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
        "Object Lock is explicitly off. A pass means the draft left it off, not that logs are immutable.",
    ),
    (
        "S3-LIFE-001",
        "Lifecycle aborts incomplete uploads, expires audit objects on the baseline window, and does not expire current workload objects.",
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
        "Data events, advanced selectors, and Insights are explicitly empty. Empty is not proof that object access is logged.",
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
        "IAM-SESSION-001",
        "Each role max_session_duration is 3600 seconds or less.",
    ),
)

NOT_ASSESSED: tuple[tuple[str, str], ...] = (
    (
        "account-and-organization-public-access-block",
        "Bucket public access blocks do not set or prove account or organization S3 Block Public Access.",
    ),
    (
        "organization-scps-rcps-permission-boundaries",
        "This plan is not an AWS Organizations policy and does not show SCPs, RCPs, or permission boundaries.",
    ),
    (
        "s3-object-lock-and-mfa-delete",
        "Object Lock and MFA Delete are not enabled. Versioning alone does not make logs immutable.",
    ),
    (
        "s3-server-access-logging",
        "S3 server access logging is not configured. CloudTrail management events are not object access logs.",
    ),
    (
        "cloudtrail-data-events",
        "S3 object-level data events are not enabled. Management events do not record GetObject or PutObject data events.",
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
        "GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and Macie are not deployed or queried.",
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
