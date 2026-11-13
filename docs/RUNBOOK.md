# Runbook

Draft. The only procedure run for this repository is the local one. There is no apply procedure.

## Local review

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
PYTHONPATH=src .venv/bin/pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform init -backend=false -input=false
terraform -chdir=terraform validate
./scripts/offline-plan.sh
PYTHONPATH=src python3 -m aws_baseline_evidence assess \
  tests/fixtures/generated/offline.plan.json --format text
PYTHONPATH=src python3 -m aws_baseline_evidence assess \
  tests/fixtures/synthetic-compliant.json --format text
```

Read the banner in the text output before the findings. `deployed_aws_verified` is always false. Synthetic files are labeled `synthetic_fixture`. The file written by `scripts/offline-plan.sh` is `terraform_plan_json`.

Exit 0 is only for a file where every assessed finding passed. The generated offline plan from this draft exits 3 because KMS key ids are not known until apply. That is the expected fail-safe result, not a failed Terraform configuration. `terraform validate` was successful.

The bucket policies deny a `PutObject` that omits `x-amz-server-side-encryption`. Default SSE-KMS does not cover that request. The CloudTrail security best-practices example assumes CloudTrail sends `aws:kms` or `AES256`. An IAM caller who sends `AES256` to the audit bucket is denied.

Do not pipe plan JSON from an untrusted source into a shell. The checker does not shell out, but the surrounding shell might.

## If someone later proposes an apply

This draft does not authorize that. A future change would have to replace `terraform/providers.tf` before any real authentication is possible. Until that replacement, the placeholder access key cannot authenticate.

Costs below are published list rates fetched on 2026-11-08, not a measured bill. S3 storage and request rates were not copied because the S3 pricing page was not retrieved for a per-GB figure. See https://aws.amazon.com/s3/pricing/ before estimating storage.

From the CloudTrail pricing page:

- One copy of management events delivered to S3 is described as free, with limits.
- Additional copies of management events: $2.00 per 100,000 events.
- Data events: $0.10 per 100,000 events delivered (re-read 13 November 2026). This stack enables S3 object data events for the workload bucket only, so every object call on that bucket is billed at this rate. No volume was measured.
- Network activity events: $0.10 per 100,000. Not enabled.
- Insights for management events: $0.35 per 100,000 events analyzed per insight type. Not enabled.
- Delivery to CloudWatch Logs: $0.25 per GB, plus CloudWatch ingestion. Not enabled.
- The pricing example says S3 storage and analysis are extra.

From the KMS pricing page:

- Each customer managed key is $1 per month, prorated hourly. This stack plans two keys, so the published key storage charge starts at $2 per month before rotation.
- The first and second rotation of key material each add $1 per month, capped at the second rotation. After two rotations, the page's cap is $3 per month per key.
- 20,000 requests per month are free across Regions. The S3 example on that page prices further symmetric requests at $0.03 per 10,000.
- A key pending deletion is not charged. Canceling deletion resumes charges as though deletion was never scheduled.

The S3 Bucket Keys page says a bucket key can reduce KMS request costs by up to 99 percent. That is AWS's statement. This draft did not measure it. Both buckets set `bucket_key_enabled` to true.

Event history is separate from the trail. The pricing page describes the most recent 90 days of management events as available at no additional charge. The concepts page calls event history an immutable record of the past 90 days. This stack does not configure event history; it is not the trail and it is not object-level logging.

A misconfigured trail retries delivery for 30 days, and the bucket-policy page says those attempts are charged until the trail is deleted.

There is no NAT gateway, EC2 instance, or CloudWatch log group in the Terraform, so those charges are not created by an unchanged apply. They appear if a later change adds them.

## Teardown risks, if a deployment existed

Not executed. Documented so a reviewer can see them.

- `force_destroy` is false. `terraform destroy` does not empty versioned buckets. The audit bucket policy denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal, so an API delete of log objects requires removing `DenyAuditObjectDelete` first. There is no break-glass principal. S3 Lifecycle expiration still removes audit objects, because lifecycle does not call `DeleteObject`. Workload objects can be deleted by the workload role under `app/`, and version cleanup is still manual or by lifecycle. That deletion is not scripted here.
- Versioning cannot be switched off after it has been enabled; it can be suspended. Suspension is not in this plan.
- Audit lifecycle deletes current log objects after `audit_log_retention_days` (default 365) and noncurrent versions after `audit_noncurrent_version_days` (default 365; the plan fails if it is below the retention window). Workload current objects are not expired. Workload noncurrent versions expire after 30 days by default.
- If `audit_object_lock_mode` was set, Object Lock cannot be turned off and locked versions cannot be deleted until retention ends. In COMPLIANCE mode no user, including root, can shorten that. Choose the mode before the first apply.
- `terraform destroy` on `aws_s3_account_public_access_block.account` is expected to remove the account-wide setting for every bucket in the account. Not tested. Remove the resource from state instead if the account setting must stay.
- Destroying the trail does not delete the log objects. Leaving a broken trail in place can incur the 30 day redelivery charges described above.
- Scheduling KMS deletion starts a 30 day window in this plan. The delete-key page says the key cannot be used during that window, and that symmetric ciphertext cannot be decrypted after the key is deleted. Cancel during the window if the objects are still needed. The actual deletion time can be up to 24 hours longer than the scheduled period.
- Deleting the buckets returns their names to the shared global namespace. The S3 security page says another account can then create the same name.
- IAM roles and inline policies are destroyed with the stack. They do not by themselves hold data.
- No remote backend is configured. Local state, if an apply were ever run, would contain resource ids and should not be committed. `*.tfstate` is gitignored. This draft produced no state file.

## Evidence files from this draft

| File | Class | Result |
| --- | --- | --- |
| `docs/evidence/synthetic-compliant.txt` | synthetic fixture | exit 0, 53 pass, 0 fail, 0 unknown |
| `docs/evidence/synthetic-noncompliant.txt` | synthetic fixture | exit 1, 32 pass, 19 fail, 2 unknown |
| `docs/evidence/synthetic-unknown.txt` | synthetic fixture | exit 3, 40 pass, 0 fail, 13 unknown |
| `docs/evidence/generated-offline-plan.txt` | `terraform show -json` | exit 3, 47 pass, 0 fail, 6 unknown |

Regenerated 13 November 2026. Those files are checker output. They are not AWS API responses.
