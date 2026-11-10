terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Validated in this draft: hashicorp/aws 5.100.0 with Terraform 1.17.1.
      # 5.100.0 does not accept recursive_logging; that argument appears in newer provider docs.
      version = "5.100.0"
    }
  }
}
