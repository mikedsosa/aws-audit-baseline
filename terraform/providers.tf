# The provider block is pinned so this draft cannot authenticate to AWS.
# access_key and secret_key are placeholders, not credentials. They override the
# default credential chain, including ambient environment credentials.
# skip_* stops the provider from calling STS or the instance metadata service
# during a local plan. Removing these lines would be a separate change and is
# not part of this draft. Do not replace the placeholders with a real key.
provider "aws" {
  region                      = var.aws_region
  access_key                  = "offline-plan-not-a-credential"
  secret_key                  = "offline-plan-not-a-credential"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
