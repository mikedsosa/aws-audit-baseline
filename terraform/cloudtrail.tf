resource "aws_cloudtrail" "audit_logs" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.audit_logs.bucket
  s3_key_prefix                 = local.log_prefix
  kms_key_id                    = aws_kms_alias.audit_logs.arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = false

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Object-level read and write data events for the workload bucket only.
    # The audit bucket is not listed, so log delivery is not logged as a data
    # event. Data events are billed per event; see docs/RUNBOOK.md.
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${local.data_bucket_arn}/"]
    }
  }

  tags = merge(local.common_tags, {
    BaselineComponent = "audit-logs"
  })

  depends_on = [
    aws_s3_bucket_policy.audit_logs,
    aws_kms_key.audit_logs,
  ]
}
