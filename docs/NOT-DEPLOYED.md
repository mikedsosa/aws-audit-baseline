# Not deployed

This file is the deployment record for the draft: nothing was deployed.

| Check | Result |
| --- | --- |
| AWS account | None configured. No account id was discovered from STS. |
| Credentials | `terraform/providers.tf` sets `access_key` and `secret_key` to `offline-plan-not-a-credential` and skips credential validation, account id lookup, and the EC2 metadata service. |
| `terraform apply` | Not run. |
| `terraform plan` | Run locally with `-refresh=false`, `-lock=false`, and `examples/offline.tfvars`. The var-file account `123456789012` is an example number, not an account this draft owns. The user ARNs are placeholders. |
| `terraform validate` | Succeeded with Terraform 1.17.1 and hashicorp/aws 5.100.0. |
| State file | None created. |
| Resources in AWS | None created by this draft. |
| Checker AWS calls | None. The CLI has no AWS SDK dependency. |

`tests/fixtures/generated/offline.plan.json` includes `"applyable": true` because that is how Terraform 1.17.1 marks a plan it was able to build. Apply was not invoked. The same file repeats the placeholder credential inside `configuration.provider_config`. That string is not a secret and must not be replaced with a real key in this draft.

Checker output for that plan is `docs/evidence/generated-offline-plan.txt`. `deployed_aws_verified` is false. The result is unknown, exit 3, because KMS identifiers are known only after apply.

Synthetic JSON under `tests/fixtures/synthetic-*.json` is hand-built. Its `_aws_baseline_fixture` object says `not_deployed_aws` is true. The checker rejects any other fixture kind. Those files are not `terraform show` output.

The constant Terraform output `deployment_status` is `not-deployed-by-this-draft`. The checker fails the plan if that output is changed to another string. The output is still only a string in a plan.
