variable "account_id" {
  type        = string
  description = "12-digit AWS account ID copied into ARNs. This draft does not call STS and is not bound to a real account."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be exactly 12 digits."
  }
}

variable "aws_region" {
  type        = string
  description = "Home Region for the trail, both KMS keys, and both buckets. CreateTrail reports KmsKeyNotFoundException when the trail bucket and KMS key are in different Regions."
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must look like a Region name, for example us-east-1."
  }
}

variable "aws_partition" {
  type        = string
  description = "ARN partition. Documentation for this draft was read for the commercial partition aws. aws-us-gov and aws-cn are accepted only so the partition is not hardcoded; their service behavior was not reviewed."
  default     = "aws"

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.aws_partition)
    error_message = "aws_partition must be aws, aws-us-gov, or aws-cn."
  }
}

variable "name_prefix" {
  type        = string
  description = "Short lowercase prefix used in resource names. The default is a draft label, not a deployed system name."
  default     = "studybase"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-20 characters, lowercase letters, digits, and hyphens, and must start and end with a letter or digit."
  }
}

variable "workload_trusted_user_arns" {
  type        = list(string)
  description = "IAM user ARNs allowed to assume the workload role. AssumeRole requires MFA. Role ARNs are rejected because role-chain MFA was not validated."

  validation {
    condition = (
      length(var.workload_trusted_user_arns) >= 1 &&
      length(var.workload_trusted_user_arns) <= 3 &&
      alltrue([
        for arn in var.workload_trusted_user_arns :
        startswith(arn, "arn:${var.aws_partition}:iam::${var.account_id}:user/")
      ])
    )
    error_message = "Provide 1 to 3 IAM user ARNs in this account and partition."
  }
}

variable "auditor_trusted_user_arns" {
  type        = list(string)
  description = "IAM user ARNs allowed to assume the auditor role. AssumeRole requires MFA."

  validation {
    condition = (
      length(var.auditor_trusted_user_arns) >= 1 &&
      length(var.auditor_trusted_user_arns) <= 3 &&
      alltrue([
        for arn in var.auditor_trusted_user_arns :
        startswith(arn, "arn:${var.aws_partition}:iam::${var.account_id}:user/")
      ])
    )
    error_message = "Provide 1 to 3 IAM user ARNs in this account and partition."
  }
}

variable "audit_log_retention_days" {
  type        = number
  description = "Current-object retention for CloudTrail log objects and digest files. S3 lifecycle expiration deletes them after this many days. This is not Object Lock."
  default     = 365

  validation {
    condition     = var.audit_log_retention_days >= 365 && var.audit_log_retention_days <= 3650
    error_message = "audit_log_retention_days must be from 365 through 3650."
  }
}

variable "audit_noncurrent_version_days" {
  type        = number
  description = "Days before noncurrent versions in the audit bucket expire. Must be at least audit_log_retention_days, so an overwrite cannot remove a log version before the stated retention."
  default     = 365

  validation {
    condition     = var.audit_noncurrent_version_days >= 365 && var.audit_noncurrent_version_days <= 3650
    error_message = "audit_noncurrent_version_days must be from 365 through 3650."
  }
}

variable "audit_object_lock_mode" {
  type        = string
  description = "OFF, GOVERNANCE, or COMPLIANCE. Anything other than OFF creates the audit bucket with Object Lock and a default retention of audit_log_retention_days. Object Lock cannot be turned off after it is on, and COMPLIANCE retention cannot be shortened or removed by any user, including root."
  default     = "OFF"

  validation {
    condition     = contains(["OFF", "GOVERNANCE", "COMPLIANCE"], var.audit_object_lock_mode)
    error_message = "audit_object_lock_mode must be OFF, GOVERNANCE, or COMPLIANCE."
  }
}

variable "workload_noncurrent_version_days" {
  type        = number
  description = "Days before noncurrent versions in the workload bucket expire. Current workload objects are not expired by this stack."
  default     = 30

  validation {
    condition     = var.workload_noncurrent_version_days >= 7 && var.workload_noncurrent_version_days <= 90
    error_message = "workload_noncurrent_version_days must be from 7 through 90."
  }
}
