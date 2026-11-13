# Limits

Draft, pending independent fact-check. The checker is a review aid for one Terraform plan shape. It is not a policy engine and not a certification.

## Rule behavior

- Required controls that are absent from the planned value fail.
- Attributes marked unknown in `after_unknown`, including values Terraform will only know after apply, are unknown.
- A file with any unknown and no fail exits 3.
- Provider defaults are not filled in. An omitted `enable_log_file_validation` does not pass just because a human remembers a default.
- `CT-DATA-001` passes only when the single `data_resource` is `AWS::S3::Object` for the workload bucket ARN with a trailing slash, and the advanced and Insights selector lists are present and empty. Changed 13 November 2026; before that, an empty `data_resource` list was required.
- `S3-LOCK-001` passes on the workload bucket only when Object Lock is explicitly false. On the audit bucket it passes when Object Lock is explicitly false, with a reason that says the pass is not an immutability control, or when Object Lock is on with one GOVERNANCE or COMPLIANCE default retention of at least 365 days.
- `S3-RET-001` checks every enabled audit lifecycle rule against the 365 day floor. An expiration by date fails because the checker cannot compare a date to a retention period.
- `KMS-SCOPE-001` and `IAM-TAMPER-001` are deny-list style invariants. They cover the actions listed in `catalog.py`, not every action AWS has.
- Unsupported resource types produce `UNSUPPORTED-TYPE-001` as unknown, so an extra instance cannot hide inside a pass.
- Provisioners fail `PROV-001`. The process does not run them.
- The input cannot set `deployed_aws_verified`. Fixture metadata must say `kind` is `synthetic` and `not_deployed_aws` is true, or the file is rejected. Real `terraform show -json` has no fixture metadata and is labeled `terraform_plan_json`.

The rule ids and the permanent `not_assessed` list are in [RULES.md](RULES.md).

## Input handling

- UTF-8 JSON only. The standard-library parser is the only parser. There is no `eval`, `pickle`, YAML loader, or shell.
- Default maximum file size is 2,000,000 bytes. `--max-bytes` cannot exceed 8,000,000.
- Nesting deeper than 64, more than 400 resource changes, or a string longer than 200,000 characters is an input error (exit 2).
- A state file without `resource_changes` is rejected.
- Policy documents that use `NotPrincipal`, `NotAction`, `NotResource`, or a condition operator other than the exact operator the rule expects are unknown, not pass.
- Duplicate JSON object keys follow Python's last-key-wins `json.loads` behavior.

## Generated plan versus synthetic fixture

`tests/fixtures/generated/offline.plan.json` was produced by Terraform 1.17.1 and AWS provider 5.100.0. Its unknown findings are the alias target and the KMS key id on encryption and on the trail. The synthetic compliant fixture fills those values with placeholder key ids `11111111-1111-4111-8111-111111111111` and `22222222-2222-4222-8222-222222222222`. Those ids are not keys in an account. Passing the synthetic file does not mean the generated plan passed, and neither file means a bucket exists.

The generated file contains `"applyable": true` and the placeholder `offline-plan-not-a-credential`. See [NOT-DEPLOYED.md](NOT-DEPLOYED.md).

## Known gaps in the Terraform itself

- Account-level Block Public Access is set by `terraform/account.tf` since 13 November 2026. It applies to every bucket in the account, and an account managed by an organization-level S3 policy rejects the call. Organization-level Block Public Access is not set.
- The CloudTrail `kms:Decrypt` statement matches the published example and has no `aws:SourceArn` condition. The encrypt and describe statements have that condition.
- An Allow principal must be only the expected service or the expected IAM users. An extra `AWS: "*"` or `Federated: "*"` fails. This was added after a crafted plan with those extra identities still exited 0.
- `exclude_management_event_sources` must be empty or null. A non-empty list fails `CT-DATA-001`.
- `LookupEvents`, `DescribeTrails`, and `ListTrails` are on `Resource "*"`. AWS's service reference JSON for CloudTrail, read 13 November 2026, lists no resource types for those three actions, so `*` is required.
- The audit bucket denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal. There is no break-glass principal. S3 Lifecycle expiration does not call `DeleteObject`, so the deny does not stop the retention rule. See the lifecycle troubleshooting page read on 10 November 2026.
- The bucket policies use `StringNotEquals` on `s3:x-amz-server-side-encryption`. A request that omits the header is denied before default SSE-KMS applies. The CloudTrail security best-practices example assumes CloudTrail sends `aws:kms` or `AES256`. On the audit bucket, `StringNotEqualsIfExists` keeps that allowance to CloudTrail. An IAM caller who sends `AES256` is denied.
- GuardDuty, AWS Config, and Security Hub are not resources in this stack. The checker does not emit a pass for them. tfsec 1.28.14 did not flag their absence; it did flag missing S3 server access logging and CloudWatch Logs delivery for the trail.
- The workload key policy requires `kms:EncryptionContext:aws:s3:arn` to equal the bucket ARN, because the Bucket Keys page says bucket keys use the bucket ARN as encryption context. The condition-key spelling was not confirmed with an AWS API call. A wrong spelling would deny the workload role at apply time rather than grant a wider key.
- Object Lock is opt-in through `audit_object_lock_mode` and off in the example. It cannot be turned off after it is enabled. S3 data events are on for the workload bucket only. MFA Delete, server access logs, and digest validation jobs are absent on purpose. See `docs/REVIEW-2026-11-13.md`.
- The audit bucket policy does not deny an IAM caller who overwrites a log object with `aws:kms`. The old version is kept as noncurrent for at least 365 days.
- The workload bucket policy does not pin uploads to the workload key id. The S3 SSE-KMS page says a request with `aws:kms` and no key id uses the AWS managed key.
- Provider 5.100.0 has no `recursive_logging` argument. The CreateTrail default remains in force and is not assessed.
- Commercial-partition pages were the ones read. `aws_partition` accepts `aws-us-gov` and `aws-cn` only so ARNs are not hardcoded. Their behavior was not reviewed.
- No remote state, no CI apply, no drift detection.

## Evidence hashes

`input.sha256` is the SHA-256 of the raw plan bytes. `ruleset.files_sha256` is the SHA-256 of the names and contents of `catalog.py`, `lookup.py`, `plan.py`, `policy.py`, and `rules.py`. `evidence_content_sha256` is the SHA-256 of the canonical JSON document with sorted keys and compact separators, excluding the hash field itself. There is no timestamp in the evidence document. The plan file Terraform writes does contain a timestamp, so regenerating the plan changes `input.sha256`.
