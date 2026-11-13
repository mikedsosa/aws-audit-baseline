# AWS audit baseline

Released under the MIT License; see [LICENSE](LICENSE). Nothing in it was deployed, and the commands below did not use AWS credentials or create cloud resources.

## Problem

A small study stack can look locked down in Terraform and still be wrong: a bucket policy can grant CloudTrail and also grant everyone, a trail can say it logs management events while dropping KMS events, and a plan can omit values that Terraform will only know after apply. This repository is a reviewable baseline for one private S3 workload and its audit trail, plus a local checker that scores a Terraform plan file without calling AWS.

## Approach

The Terraform in `terraform/` describes one account and one home Region:

- a workload bucket and a separate CloudTrail bucket
- a customer managed KMS key for each bucket
- one multi-Region trail for management events and workload bucket object data events, with log file validation on and organization trail off
- account-level S3 Block Public Access for that account
- optional S3 Object Lock on the audit bucket (`audit_object_lock_mode`, default `OFF`)
- two IAM roles that require MFA and trust only IAM users in that account

The workload role is limited to the `app/` prefix. The auditor role can read and list only the `cloudtrail/` prefix. Both bucket policies deny insecure transport. Both also deny `PutObject` when `s3:x-amz-server-side-encryption` is not `aws:kms`. That check is `StringNotEquals`, so a request that omits the header is denied before default encryption applies. Default SSE-KMS does not cover that request. On the audit bucket, the same deny uses `StringNotEqualsIfExists` on `aws:PrincipalServiceName`. An IAM caller has no service name, so an IAM upload that sends `AES256` is denied. Callers other than CloudTrail stay on `aws:kms` only. A separate deny lets CloudTrail send `aws:kms` or `AES256`. The CloudTrail security best-practices page says to allow AES256 alongside `aws:kms` when SSE-KMS and log file validation are used, and it shows that condition. The example assumes CloudTrail sends `aws:kms` or `AES256`. The page was read on 10 November 2026: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html. The audit bucket also denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal. There is no break-glass principal. S3 Lifecycle expiration does not call `DeleteObject`, so that deny does not stop the retention rule.

`aws-baseline-evidence` reads one plan JSON file. It does not apply the plan, call AWS, or execute strings from the file. A missing required value fails. An unknown planned value is unknown. Neither counts as a pass. Exit codes are 0 for all pass, 1 for any fail, 2 for a file the checker will not read, and 3 for unknown results with no fail. The report says it is not a compliance certification, and `deployed_aws_verified` is false.

GuardDuty, AWS Config, and Security Hub are not part of this stack. Each can be enabled per account or organization-wide with a delegated administrator. AWS pricing says the included capabilities are consolidated under Security Hub rather than billed twice; remaining GuardDuty capabilities stay on GuardDuty's bill. The pricing page is the source of truth: https://aws.amazon.com/security-hub/pricing/ , read on 10 November 2026. This draft does not define or enable them. A passing report does not mean those services are on.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Terraform 1.17.1 and the AWS provider 5.100.0 were used for the checks below. The provider block uses the placeholder `offline-plan-not-a-credential` and skips credential validation, account lookup, and the instance metadata service. That placeholder is not a key.

```bash
PYTHONPATH=src .venv/bin/pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform init -backend=false -input=false
terraform -chdir=terraform validate
./scripts/offline-plan.sh
PYTHONPATH=src python3 -m aws_baseline_evidence assess \
  tests/fixtures/generated/offline.plan.json --format text
```

`./scripts/offline-plan.sh` unsets ambient AWS credential variables, sets `AWS_EC2_METADATA_DISABLED=true`, and runs `terraform plan -input=false -lock=false -refresh=false` with `examples/offline.tfvars`. The account number in that file, `123456789012`, is an example. It is not an account this draft owns.

## Results

These numbers are from this workspace on 10 November 2026, before and after the review fixes. The starting commit was `04b837badc186ed5322dba5329e21c2a1960bbb1`.

Before the fixes, on that commit:

| Command | Result |
| --- | --- |
| `PYTHONPATH=src .venv/bin/pytest` | 22 passed |
| `.venv/bin/ruff check src tests` | All checks passed |
| `.venv/bin/ruff format --check src tests` | 16 files already formatted |
| `terraform -chdir=terraform fmt -check -recursive` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| offline plan | 23 to add, 0 to change, 0 to destroy |

Checker totals before the fixes:

| File | Pass | Fail | Unknown | Exit |
| --- | --- | --- | --- | --- |
| `tests/fixtures/synthetic-compliant.json` | 44 | 0 | 0 | 0 |
| `tests/fixtures/synthetic-noncompliant.json` | 25 | 17 | 2 | 1 |
| `tests/fixtures/synthetic-unknown.json` | 33 | 0 | 11 | 3 |
| fresh `terraform show -json` plan | 38 | 0 | 6 | 3 |

The six unknowns were KMS key and alias identifiers: `S3-ENC-001` twice, `KMS-ALIAS-001` twice, `KMS-SEP-001`, and `CT-DEST-001`.

After the fact-check fixes, the same commands were run again:

| Command | Result |
| --- | --- |
| `PYTHONPATH=src .venv/bin/pytest` | 36 passed |
| `PYTHONPATH=src .venv/bin/pytest --collect-only -q` | 36 tests collected |
| `.venv/bin/ruff check src tests` | All checks passed |
| `.venv/bin/ruff format --check src tests` | 17 files already formatted |
| `terraform -chdir=terraform fmt -check -recursive` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| `terraform plan -input=false -lock=false -refresh=false` | 23 to add, 0 to change, 0 to destroy |

Checker totals after those fixes:

| File | Pass | Fail | Unknown | Exit |
| --- | --- | --- | --- | --- |
| `tests/fixtures/synthetic-compliant.json` | 47 | 0 | 0 | 0 |
| `tests/fixtures/synthetic-noncompliant.json` | 27 | 18 | 2 | 1 |
| `tests/fixtures/synthetic-unknown.json` | 34 | 0 | 13 | 3 |
| `tests/fixtures/generated/offline.plan.json` | 41 | 0 | 6 | 3 |

The generated plan is still unknown, exit 3, for the same six KMS identifier findings. Terraform 1.17.1 wrote `"applyable": true` in that file. The plan was not applied.

Other scans after the fixes:

- `tfsec terraform --no-color --format json --soft-fail` with tfsec 1.28.14 reported 3 results: `AVD-AWS-0162` low, CloudTrail has no CloudWatch Logs destination; `AVD-AWS-0089` medium, twice, neither bucket has S3 server access logging. Checkov was not run.
- `gitleaks detect --source /workspace --no-git --redact` with gitleaks 8.28.0 reported no leaks after scanning about 834 KB.
- `.venv/bin/pip-audit` reported no known vulnerabilities in the 33 packages installed in this virtualenv. `pyproject.toml` lists no runtime dependencies for the checker.

Copies of the checker output are in `docs/evidence/`.

### Review of 13 November 2026

An independent review of `b2085aa` is in [docs/REVIEW-2026-11-13.md](docs/REVIEW-2026-11-13.md), with control mappings in [docs/CONTROL-MAPPING.md](docs/CONTROL-MAPPING.md). It found 3 high, 7 medium, 7 low, and 1 informational item. 7 were fixed in Terraform, the checker, or both. H-3 (Object Lock) was partly fixed as an opt-in. The informational item was closed by reading the AWS service reference. The other 9 are deferred, with reasons. New rules: `S3-ACCT-BPA-001`, `S3-RET-001`, `KMS-SCOPE-001`, `IAM-TAMPER-001`.

Results after those changes, same tool versions, run locally on 13 November 2026:

| Command | Result |
| --- | --- |
| `PYTHONPATH=src .venv/bin/pytest` | 76 passed |
| `PYTHONPATH=src .venv/bin/pytest --collect-only -q` | 76 tests collected |
| `.venv/bin/ruff check src tests` | All checks passed |
| `.venv/bin/ruff format --check src tests` | 18 files already formatted |
| `terraform -chdir=terraform fmt -check -recursive` | exit 0 |
| `terraform -chdir=terraform validate` | Success. The configuration is valid. |
| `./scripts/offline-plan.sh` | 24 resources to create, 0 to change, 0 to destroy |

| File | Pass | Fail | Unknown | Exit |
| --- | --- | --- | --- | --- |
| `tests/fixtures/synthetic-compliant.json` | 53 | 0 | 0 | 0 |
| `tests/fixtures/synthetic-object-lock.json` | 53 | 0 | 0 | 0 |
| `tests/fixtures/synthetic-noncompliant.json` | 32 | 19 | 2 | 1 |
| `tests/fixtures/synthetic-unknown.json` | 40 | 0 | 13 | 3 |
| `tests/fixtures/generated/offline.plan.json` | 47 | 0 | 6 | 3 |
| the `b2085aa` generated plan, scored by the new rules | 40 | 7 | 6 | 1 |

The six unknowns are the same KMS identifiers as before. Nothing was applied.

## Limitations

- No AWS account was contacted. Validate and plan do not show that CloudTrail can deliver to the bucket or that the KMS policies work.
- The six unknown findings on a real plan are key ids AWS assigns at apply time. The synthetic compliant file fills those ids with placeholders. A pass on that file is not a pass on the generated plan, and neither file means a bucket exists.
- The audit bucket denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for every principal. There is no break-glass principal, so an API delete requires a policy change. S3 Lifecycle expiration still removes objects because it does not call `DeleteObject`. That is documented at https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshoot-lifecycle.html, read on 10 November 2026. Object Lock is opt-in and off in the example. MFA Delete is off because it cannot be used with lifecycle. Noncurrent audit versions are kept at least as long as current ones (default 365 days).
- The CloudTrail `kms:Decrypt` statement has no `aws:SourceArn` condition. That matches the statement in the CloudTrail KMS key policy documentation used for this draft. The checker now rejects an extra `AWS: "*"` principal on that statement.
- Both key policies still allow this account's root `kms:*`. Other IAM in the account is invisible to the checker.
- `LookupEvents`, `DescribeTrails`, and `ListTrails` are allowed on `Resource "*"`. AWS's CloudTrail service reference lists no resource types for them.
- Bucket and account Block Public Access are planned. The account setting affects every bucket in the account and is rejected where an organization-level S3 policy manages it. Organization settings are not set.
- `S3-SSE-001` keeps callers other than CloudTrail on `aws:kms`. CloudTrail may send `aws:kms` or `AES256`. The CloudTrail security best-practices page says to allow AES256 alongside `aws:kms` when SSE-KMS and log file validation are used, and it shows that condition. A request that omits `x-amz-server-side-encryption` is denied by these `StringNotEquals` statements before default encryption applies. An IAM caller who sends `AES256` to the audit bucket is denied, because `aws:PrincipalServiceName` is absent and that deny uses `StringNotEqualsIfExists`.
- Data events for anything other than workload bucket objects, Insights, CloudTrail Lake, CloudWatch Logs, EventBridge, and S3 server access logs are not in the stack. GuardDuty, AWS Config, and Security Hub are not in it either. Each of those three can be enabled per account or organization-wide with a delegated administrator. AWS pricing says the included capabilities are consolidated under Security Hub rather than billed twice; remaining GuardDuty capabilities stay on GuardDuty's bill. See https://aws.amazon.com/security-hub/pricing/ . tfsec flagged the missing CloudWatch destination and the missing S3 access logs. Those were left out on purpose.
- Docs that explain the AWS behavior are still a draft. The pages listed in `docs/SOURCES.md` were fetched on 8 November 2026, except the rows that say they were read on 10 or 13 November 2026.
