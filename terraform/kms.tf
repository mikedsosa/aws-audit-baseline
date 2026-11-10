resource "aws_kms_key" "workload_data" {
  description              = "Customer managed key for the private workload bucket."
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  rotation_period_in_days  = 365
  deletion_window_in_days  = 30
  is_enabled               = true
  multi_region             = false
  policy                   = local.workload_key_policy

  tags = merge(local.common_tags, {
    BaselineComponent = "workload-data"
  })
}

resource "aws_kms_alias" "workload_data" {
  name          = local.data_key_alias
  target_key_id = aws_kms_key.workload_data.key_id
}

resource "aws_kms_key" "audit_logs" {
  description              = "Customer managed key for CloudTrail log and digest objects."
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  rotation_period_in_days  = 365
  deletion_window_in_days  = 30
  is_enabled               = true
  multi_region             = false
  policy                   = local.audit_key_policy

  tags = merge(local.common_tags, {
    BaselineComponent = "audit-logs"
  })
}

resource "aws_kms_alias" "audit_logs" {
  name          = local.logs_key_alias
  target_key_id = aws_kms_key.audit_logs.key_id
}
