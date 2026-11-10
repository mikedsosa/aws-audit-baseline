# Synthetic inputs for local validate and offline plan.
# 123456789012 is an example account number, not an account this draft owns.
# The user ARNs are placeholders. They are not real IAM users.

account_id = "123456789012"
aws_region = "us-east-1"
aws_partition = "aws"
name_prefix   = "studybase"

workload_trusted_user_arns = [
  "arn:aws:iam::123456789012:user/ExampleWorkloadOperator",
]

auditor_trusted_user_arns = [
  "arn:aws:iam::123456789012:user/ExampleAuditor",
]

audit_log_retention_days        = 365
audit_noncurrent_version_days   = 30
workload_noncurrent_version_days = 30
