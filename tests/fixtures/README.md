# Fixtures

`synthetic-*.json` files are hand-built plan-shaped JSON. Each one has `_aws_baseline_fixture.kind` set to `synthetic` and `not_deployed_aws` set to true. They use example account `123456789012` and placeholder KMS key ids. They are not `terraform show` output and they are not evidence of an AWS account.

`generated/offline.plan.json` is `terraform show -json` from Terraform 1.17.1 and hashicorp/aws 5.100.0. The plan was not applied. Terraform marked it `applyable`. The provider configuration in the file contains the placeholder `offline-plan-not-a-credential`, which is not a credential.

Regenerate the offline plan with `./scripts/offline-plan.sh`. Regenerating changes the timestamp inside the plan file and therefore the evidence input hash.
