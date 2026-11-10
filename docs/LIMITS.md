# Limits

Draft, pending independent fact-check. The checker is a review aid for one Terraform plan shape. It is not a policy engine and not a certification.

## Rule behavior

- Required controls that are absent from the planned value fail.
- Attributes marked unknown in `after_unknown`, including values Terraform will only know after apply, are unknown.
- A file with any unknown and no fail exits 3.
- Provider defaults are not filled in. An omitted `enable_log_file_validation` does not pass just because a human remembers a default.
- Empty `data_resource`, `advanced_event_selector`, and `insight_selector` lists pass `CT-DATA-001` only when those lists are present. The pass reason says object access is not logged.
- `S3-LOCK-001` passes only when Object Lock is explicitly false. The reason says that pass is not an immutability control.
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

- Account and organization Block Public Access are not set. The Block Public Access page says a bucket policy can be edited to disable a bucket-level block, which is why it recommends the account setting.
- The CloudTrail `kms:Decrypt` statement matches the published example and has no `aws:SourceArn` condition. The encrypt and describe statements have that condition.
- An Allow principal must be only the expected service or the expected IAM users. An extra `AWS: "*"` or `Federated: "*"` fails. This was added after a crafted plan with those extra identities still exited 0.
- `exclude_management_event_sources` must be empty or null. A non-empty list fails `CT-DATA-001`.
- `LookupEvents`, `DescribeTrails`, and `ListTrails` are on `Resource "*"`. Resource-level support for those actions was not re-read from the Service Authorization Reference.
- The audit bucket denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal. There is no break-glass principal. S3 Lifecycle expiration does not call `DeleteObject`, so the deny does not stop the retention rule. See the lifecycle troubleshooting page read on 10 November 2026.
- The bucket policies use `StringNotEquals` on `s3:x-amz-server-side-encryption`. A request that omits the header is denied before default SSE-KMS applies. The CloudTrail security best-practices example assumes CloudTrail sends `aws:kms` or `AES256`. On the audit bucket, `StringNotEqualsIfExists` keeps that allowance to CloudTrail. An IAM caller who sends `AES256` is denied.
- GuardDuty, AWS Config, and Security Hub are not resources in this stack. The checker does not emit a pass for them. tfsec 1.28.14 did not flag their absence; it did flag missing S3 server access logging and CloudWatch Logs delivery for the trail.
- The workload key policy requires `kms:EncryptionContext:aws:s3:arn` to equal the bucket ARN, because the Bucket Keys page says bucket keys use the bucket ARN as encryption context. The condition-key spelling was not confirmed with an AWS API call. A wrong spelling would deny the workload role at apply time rather than grant a wider key.
- Object Lock, MFA Delete, server access logs, data events, and digest validation jobs are absent on purpose.
- Provider 5.100.0 has no `recursive_logging` argument. The CreateTrail default remains in force and is not assessed.
- Commercial-partition pages were the ones read. `aws_partition` accepts `aws-us-gov` and `aws-cn` only so ARNs are not hardcoded. Their behavior was not reviewed.
- No remote state, no CI apply, no drift detection.

## Evidence hashes

`input.sha256` is the SHA-256 of the raw plan bytes. `ruleset.files_sha256` is the SHA-256 of the names and contents of `catalog.py`, `lookup.py`, `plan.py`, `policy.py`, and `rules.py`. `evidence_content_sha256` is the SHA-256 of the canonical JSON document with sorted keys and compact separators, excluding the hash field itself. There is no timestamp in the evidence document. The plan file Terraform writes does contain a timestamp, so regenerating the plan changes `input.sha256`.
