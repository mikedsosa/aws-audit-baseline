# Rules

Draft catalog for ruleset `aws-private-audit-baseline` version `0.1.0`. A finding status is `pass`, `fail`, or `unknown`. The checker always emits every id below. Rows marked "new 2026-11-13" or "changed 2026-11-13" come from `docs/REVIEW-2026-11-13.md`.

| Id | What a pass means |
| --- | --- |
| BASE-COMP-001 | The end state has one tagged workload bucket, audit bucket, workload key, audit key, workload role, auditor role, and trail. |
| BASE-SCOPE-001 | Known ARNs agree on one account, Region, partition, and trail ARN. |
| DISCLAIM-001 | Output `deployment_status` is `not-deployed-by-this-draft`. |
| PROV-001 | Configuration is present and has no provisioners. |
| UNSUPPORTED-TYPE-001 | Every `resource_changes` entry is a supported managed type. Any other type is unknown. |
| S3-BPA-001 | Each bucket has one public access block and all four settings are true. |
| S3-ACCT-BPA-001 | New 2026-11-13. Exactly one `aws_s3_account_public_access_block` exists, its `account_id` is the plan's account, and all four settings are true. |
| S3-ENC-001 | Default encryption is `aws:kms` with a bucket key, bound to that component's alias. |
| S3-SSE-001 | The workload bucket denies PutObject unless the header is `aws:kms`. The audit bucket does the same for other callers, using `StringNotEqualsIfExists` so an IAM caller cannot send `AES256`. CloudTrail may send `aws:kms` or `AES256`. |
| S3-AUDIT-DEL-001 | The audit bucket denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal, with no break-glass condition. |
| S3-VER-001 | Versioning status is `Enabled`. |
| S3-OWN-001 | Object ownership is `BucketOwnerEnforced`. |
| S3-TLS-001 | A deny matches `s3:*` when `aws:SecureTransport` is false, on the bucket and object ARNs. |
| S3-POLICY-001 | Bucket policy statement ids are exactly the assessed set. |
| S3-DESTROY-001 | `force_destroy` is explicitly false. |
| S3-LOCK-001 | Changed 2026-11-13. Workload Object Lock is explicitly false. The audit bucket either has Object Lock explicitly false, which is not a WORM claim, or has it on with exactly one default retention rule in `GOVERNANCE` or `COMPLIANCE` mode for at least 365 days (years count as 365 days). A lock configuration on a bucket without Object Lock fails. |
| S3-LIFE-001 | Changed 2026-11-13. Multipart uploads abort within 1-7 days. Audit objects expire in 365-3650 days, and every audit noncurrent expiration is 365-3650 days. Current workload objects are not expired. Every workload noncurrent expiration is 7-90 days. |
| S3-RET-001 | New 2026-11-13. Every enabled audit lifecycle rule keeps current and noncurrent versions for at least 365 days, keeps noncurrent at least as long as current, and does not expire by date. |
| KMS-ROT-001 | Rotation is enabled and the period is 365 days. |
| KMS-WIN-001 | Deletion window is 30 days. |
| KMS-SPEC-001 | The key is enabled, symmetric, `ENCRYPT_DECRYPT`, and not multi-Region. |
| KMS-POL-001 | Changed 2026-11-13. Key policy statement ids and the baseline grants match, including account-root administration. Workload use is only `kms:Decrypt` and `kms:GenerateDataKey`. Auditor decrypt requires `kms:ViaService` for S3 in the plan Region. |
| KMS-SCOPE-001 | New 2026-11-13. Outside the account-root statement, every Allow grants only `kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKey`, or `kms:GenerateDataKey*`, names no wildcard principal, and has a condition. The CloudTrail-only `kms:Decrypt` statement is the one documented exception to the condition requirement. |
| KMS-ALIAS-001 | Exactly two aliases, and one targets this component key. |
| KMS-SEP-001 | The two buckets do not name the same KMS key id. |
| CT-FLAG-001 | Logging, log file validation, global service events, and multi-Region are true, and `is_organization_trail` is false. |
| CT-DEST-001 | The trail bucket is the audit bucket, the prefix is `cloudtrail`, and the KMS id is the audit alias. |
| CT-S3POL-001 | CloudTrail ACL and write statements match the trail ARN, account prefix, and `bucket-owner-full-control`. |
| CT-DATA-001 | Changed 2026-11-13. The management event selector is explicit. Its only data resource is `AWS::S3::Object` with the single value `<workload bucket ARN>/`. The audit bucket is never a data resource. Advanced and Insights selectors are empty lists. |
| IAM-TRUST-001 | Each role trusts only IAM users in this account and requires MFA. |
| IAM-PERM-001 | The workload policy stays on `app/`. The auditor policy is the assessed read set. |
| IAM-TAMPER-001 | New 2026-11-13. No Allow statement in a baseline role's inline policies matches, directly or by wildcard, any action in `TAMPER_ACTIONS` in `catalog.py` (trail stop, delete, update, or selector changes; bucket policy, public access block, versioning, lifecycle, Object Lock, retention, or governance bypass; key policy, grants, disable, or deletion; role policy or trust changes). |
| IAM-SESSION-001 | `max_session_duration` is 3600. |

Supported types: `aws_cloudtrail`, `aws_iam_role`, `aws_iam_role_policy`, `aws_kms_alias`, `aws_kms_key`, `aws_s3_account_public_access_block`, `aws_s3_bucket`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_object_lock_configuration`, `aws_s3_bucket_ownership_controls`, `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_versioning`.

## Not assessed

These ids are copied into every evidence file. They are not passes.

- `organization-public-access-block`
- `organization-trail-scope`
- `organization-scps-rcps-permission-boundaries`
- `s3-object-lock-default-off-and-mfa-delete`
- `s3-server-access-logging`
- `cloudtrail-data-events-other-resources`
- `cloudtrail-insights-lake-cloudwatch-eventbridge`
- `cloudtrail-digest-validation-execution`
- `cloudtrail-recursive-logging`
- `guardduty-securityhub-config-analyzer-macie`
- `network-controls`
- `sse-c-block-setting`
- `other-iam-in-the-account`
- `audit-bucket-overwrite-by-iam`
- `cloudtrail-kms-decrypt-source-arn`
- `runtime-aws-api-state`
- `shared-global-bucket-namespace`

Details are the `NOT_ASSESSED` strings in `src/aws_baseline_evidence/catalog.py`.

Control mappings for these ids are in `docs/CONTROL-MAPPING.md`.
