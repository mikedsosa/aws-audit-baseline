resource "aws_s3_bucket" "workload_data" {
  bucket              = local.data_bucket_name
  force_destroy       = false
  object_lock_enabled = false

  tags = merge(local.common_tags, {
    BaselineComponent = "workload-data"
  })
}

resource "aws_s3_bucket_public_access_block" "workload_data" {
  bucket                  = aws_s3_bucket.workload_data.bucket
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "workload_data" {
  bucket = aws_s3_bucket.workload_data.bucket

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "workload_data" {
  bucket = aws_s3_bucket.workload_data.bucket

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "workload_data" {
  bucket = aws_s3_bucket.workload_data.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_alias.workload_data.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "workload_data" {
  bucket = aws_s3_bucket.workload_data.bucket

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.workload_noncurrent_version_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.workload_data]
}

resource "aws_s3_bucket_policy" "workload_data" {
  bucket = aws_s3_bucket.workload_data.bucket
  policy = local.workload_bucket_policy

  depends_on = [aws_s3_bucket_public_access_block.workload_data]
}

resource "aws_s3_bucket" "audit_logs" {
  bucket              = local.logs_bucket_name
  force_destroy       = false
  object_lock_enabled = false

  tags = merge(local.common_tags, {
    BaselineComponent = "audit-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.bucket
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.bucket

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.bucket

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_alias.audit_logs.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.bucket

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-audit-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = var.audit_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.audit_noncurrent_version_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit_logs]
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.bucket
  policy = local.audit_bucket_policy

  depends_on = [aws_s3_bucket_public_access_block.audit_logs]
}
