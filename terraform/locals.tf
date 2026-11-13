locals {
  trail_name          = "${var.name_prefix}-management"
  workload_role_name  = "${var.name_prefix}-workload-operator"
  auditor_role_name   = "${var.name_prefix}-auditor"
  data_bucket_name    = "${var.name_prefix}-${var.account_id}-data"
  logs_bucket_name    = "${var.name_prefix}-${var.account_id}-logs"
  data_key_alias      = "alias/${var.name_prefix}-data"
  logs_key_alias      = "alias/${var.name_prefix}-logs"
  log_prefix          = "cloudtrail"
  workload_key_prefix = "app/"

  audit_object_lock_on = var.audit_object_lock_mode != "OFF"

  trail_arn         = "arn:${var.aws_partition}:cloudtrail:${var.aws_region}:${var.account_id}:trail/${local.trail_name}"
  workload_role_arn = "arn:${var.aws_partition}:iam::${var.account_id}:role/${local.workload_role_name}"
  auditor_role_arn  = "arn:${var.aws_partition}:iam::${var.account_id}:role/${local.auditor_role_name}"
  account_root_arn  = "arn:${var.aws_partition}:iam::${var.account_id}:root"
  data_bucket_arn   = "arn:${var.aws_partition}:s3:::${local.data_bucket_name}"
  logs_bucket_arn   = "arn:${var.aws_partition}:s3:::${local.logs_bucket_name}"

  common_tags = {
    BaselineStack = "private-audit-baseline"
    DraftStatus   = "not-deployed"
  }
}

locals {
  workload_bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          local.data_bucket_arn,
          "${local.data_bucket_arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyIncorrectEncryptionHeader"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.data_bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
    ]
  })

  audit_bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck20150319"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = local.logs_bucket_arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite20150319"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${local.logs_bucket_arn}/${local.log_prefix}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          local.logs_bucket_arn,
          "${local.logs_bucket_arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyNonCloudTrailIncorrectEncryptionHeader"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.logs_bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
          # aws:PrincipalServiceName is absent for an IAM caller. StringNotEqualsIfExists
          # still matches that request, so AES256 from an IAM caller is denied. CloudTrail
          # is excluded only when the service name is present and equals this value.
          # A missing s3:x-amz-server-side-encryption key makes StringNotEquals true, so
          # the deny applies before default encryption.
          StringNotEqualsIfExists = {
            "aws:PrincipalServiceName" = "cloudtrail.amazonaws.com"
          }
        }
      },
      {
        Sid    = "DenyCloudTrailIncorrectEncryptionHeader"
        Effect = "Deny"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${local.logs_bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = ["aws:kms", "AES256"]
          }
        }
      },
      {
        Sid       = "DenyAuditObjectDelete"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
        ]
        Resource = "${local.logs_bucket_arn}/*"
      },
    ]
  })

  workload_key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountRootAdministration"
        Effect = "Allow"
        Principal = {
          AWS = local.account_root_arn
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowWorkloadRoleUse"
        Effect = "Allow"
        Principal = {
          AWS = local.workload_role_arn
        }
        # The S3 SSE-KMS page lists kms:GenerateDataKey for PutObject and
        # kms:Decrypt for GetObject and multipart upload. Encrypt, ReEncrypt*,
        # and DescribeKey were removed in the 2026-11-13 review.
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.${var.aws_region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = local.data_bucket_arn
          }
        }
      },
    ]
  })

  audit_key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountRootAdministration"
        Effect = "Allow"
        Principal = {
          AWS = local.account_root_arn
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncryptLogs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${var.aws_partition}:cloudtrail:*:${var.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailDescribeKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid    = "AllowCloudTrailDecrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:Decrypt"
        Resource = "*"
      },
      {
        Sid    = "AllowAuditorDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = local.auditor_role_arn
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          Null = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "false"
          }
          # Decrypt only through S3 reads of the log objects, not direct KMS calls.
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
    ]
  })

  workload_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustedHumanUser"
        Effect = "Allow"
        Principal = {
          AWS = var.workload_trusted_user_arns
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
    ]
  })

  auditor_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustedHumanUser"
        Effect = "Allow"
        Principal = {
          AWS = var.auditor_trusted_user_arns
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
    ]
  })

  workload_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAndDeleteAppPrefix"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
        ]
        Resource = "${local.data_bucket_arn}/${local.workload_key_prefix}*"
      },
      {
        Sid      = "PutEncryptedAppPrefix"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${local.data_bucket_arn}/${local.workload_key_prefix}*"
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid      = "ListAppPrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.data_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              "${local.workload_key_prefix}*",
              local.workload_key_prefix,
            ]
          }
        }
      },
    ]
  })

  auditor_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAuditObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
        ]
        Resource = "${local.logs_bucket_arn}/cloudtrail/*"
      },
      {
        Sid    = "ListAuditBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketVersions",
        ]
        Resource = local.logs_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              "cloudtrail/*",
              "cloudtrail/",
            ]
          }
        }
      },
      {
        Sid    = "ReadTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:GetTrail",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
        ]
        Resource = local.trail_arn
      },
      {
        Sid    = "ReadTrailAccountApis"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:DescribeTrails",
          "cloudtrail:ListTrails",
        ]
        Resource = "*"
      },
    ]
  })
}
