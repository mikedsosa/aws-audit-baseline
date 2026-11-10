output "deployment_status" {
  description = "Constant disclaimer. This string in a plan is not evidence that AWS was called."
  value       = "not-deployed-by-this-draft"
}

output "workload_bucket_name" {
  description = "Planned workload bucket name. Not evidence that the bucket exists."
  value       = aws_s3_bucket.workload_data.bucket
}

output "audit_bucket_name" {
  description = "Planned CloudTrail destination bucket name. Not evidence that the bucket exists."
  value       = aws_s3_bucket.audit_logs.bucket
}

output "trail_name" {
  description = "Planned trail name. Not evidence that the trail exists."
  value       = aws_cloudtrail.audit_logs.name
}

output "workload_role_name" {
  description = "Planned workload role name."
  value       = aws_iam_role.workload_operator.name
}

output "auditor_role_name" {
  description = "Planned auditor role name."
  value       = aws_iam_role.auditor.name
}
