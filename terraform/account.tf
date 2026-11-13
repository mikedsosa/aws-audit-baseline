# Account-level S3 Block Public Access. The S3 Block Public Access page
# recommends the account setting because a bucket policy change can disable a
# bucket-level block. This resource affects every bucket in the account, and
# destroying it removes the account-level setting. Accounts under an
# organization-level S3 policy reject this call; see docs/REVIEW-2026-11-13.md.
resource "aws_s3_account_public_access_block" "account" {
  account_id              = var.account_id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
