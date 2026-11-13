# Control mapping

Draft, 13 November 2026. This table maps each checker rule to the nearest AWS Security Hub control, and through that control to a CIS AWS Foundations Benchmark v5.0.0 recommendation id and NIST SP 800-53 Rev. 5 control ids. It is a reading aid, not a compliance claim. A rule that passes here does not mean the CIS recommendation or NIST control is met.

## How the mapping was made

- CIS ids come from the Security Hub CIS v5.0.0 mapping table [C1], not from the CIS PDF, which was not read.
- NIST ids come from the "Related requirements" line of each Security Hub control page [C2, C3, C4, C5]. They were copied, not judged.
- Where Security Hub has no control that matches the rule, the row says "none found". Where the reviewer picked a NIST id by judgment, the row marks it **uncertain** and says why.
- Security Hub controls usually check a whole account. This repo checks one Terraform plan. A rule with the same idea can be narrower than the control it maps to; the "Fit" column says when.

Fit values: **direct** (same check), **partial** (same idea, narrower or different scope), **related** (supports the control, not the same check), **none found**.

## Checker rules

| Rule | Security Hub control | CIS v5.0.0 | NIST SP 800-53 Rev. 5 | Fit | Notes |
| --- | --- | --- | --- | --- | --- |
| S3-BPA-001 | S3.8 | 2.1.4 | AC-21, AC-3, AC-3(7), AC-4, AC-4(21), AC-6, SC-7, SC-7(11), SC-7(16), SC-7(20), SC-7(21), SC-7(3), SC-7(4), SC-7(9) | direct | Bucket-level block. |
| S3-ACCT-BPA-001 | S3.1 | 2.1.4 | Same list as S3.8 | direct | Account-level block. Plan only. |
| S3-ENC-001 | S3.17 | none found | SC-12(2), CM-3(6), SC-13, SC-28, SC-28(1), SC-7(10), CA-9(1), SI-7(6), AU-9 | partial | This rule also requires a bucket key and the component's alias. |
| S3-SSE-001 | none found | none found | **uncertain**: SC-28 | related | Reviewer judgment. Upload-header deny supports encryption at rest; no Security Hub control checks it. |
| S3-AUDIT-DEL-001 | none found | none found | **uncertain**: AU-9 | related | Reviewer judgment. A delete deny protects audit records, but a bucket policy does not stop lifecycle [REVIEW S1]. |
| S3-VER-001 | S3.14 | none found | AU-9(2), CP-10, CP-6, CP-6(1), CP-6(2), CP-9, SC-5(2), SI-12, SI-13(5) | direct | |
| S3-OWN-001 | S3.12 | none found | AC-2(1), AC-3, AC-3(15), AC-3(7), AC-6 | partial | S3.12 checks that ACLs are not used for access; `BucketOwnerEnforced` disables ACLs. |
| S3-TLS-001 | S3.5 | 2.1.1 | AC-17(2), AC-4, IA-5(1), SC-12(3), SC-13, SC-23, SC-23(3), SC-7(4), SC-8, SC-8(1), SC-8(2), SI-7(6) | direct | |
| S3-POLICY-001 | none found | none found | none | none found | Internal consistency check. |
| S3-DESTROY-001 | none found | none found | none | none found | Terraform-only setting. |
| S3-LOCK-001 | S3.15 | none found | CP-6(2) | partial | Passes with Object Lock off, which S3.15 would not. The pass reason says this is not a WORM claim. |
| S3-LIFE-001 | S3.13 | none found | CP-10, CP-6(2), CP-9, SC-5(2), SI-13(5) | partial | S3.13 checks that a lifecycle exists; this rule checks the day ranges. |
| S3-RET-001 | none found | none found | **uncertain**: AU-11 | related | Reviewer judgment. AU-11 is audit record retention; no Security Hub page lists it for a lifecycle check. |
| KMS-ROT-001 | KMS.4 | 3.6 | SC-12, SC-12(2), SC-28(3) | direct | |
| KMS-WIN-001 | KMS.3 | none found | SC-12, SC-12(2) | **uncertain**, related | KMS.3 checks that keys are not scheduled for deletion. A 30 day window is a different check. |
| KMS-SPEC-001 | none found | none found | none | none found | |
| KMS-POL-001 | KMS.1, KMS.2 | none found | AC-2, AC-2(1), AC-3, AC-3(15), AC-3(7), AC-5, AC-6, AC-6(3) | **uncertain**, related | KMS.1 and KMS.2 check IAM policies for KMS decrypt on all keys. This rule checks key policies. |
| KMS-SCOPE-001 | KMS.1, KMS.2 | none found | Same as KMS-POL-001 | **uncertain**, related | Same reason. Least privilege on key policies. |
| KMS-ALIAS-001 | none found | none found | none | none found | |
| KMS-SEP-001 | none found | none found | none | none found | |
| CT-FLAG-001 | CloudTrail.1, CloudTrail.4 | 3.1, 3.2 | CloudTrail.1: AC-2(4), AC-4(26), AC-6(9), AU-10, AU-12, AU-2, AU-3, AU-6(3), AU-6(4), AU-14(1), CA-7, SC-7(9), SI-3(8), SI-4(20), SI-7(8), SA-8(22). CloudTrail.4: AU-9, SI-4, SI-7(1), SI-7(3), SI-7(7) | direct | Multi-Region trail with management events, and log file validation. |
| CT-DEST-001 | CloudTrail.2 | 3.5 | AU-9, CA-9(1), CM-3(6), SC-13, SC-28, SC-28(1), SC-7(10), SI-7(6) | direct | KMS id is unknown in the offline plan, so this rule is `unknown` until apply. |
| CT-S3POL-001 | none found | none found | **uncertain**: AU-9 | related | Reviewer judgment. |
| CT-DATA-001 | S3.22, S3.23 | 3.8, 3.9 | none listed | partial | S3.22 and S3.23 look for object-level write and read logging across buckets. This stack logs one bucket only. |
| IAM-TRUST-001 | none found | none found | none | none found | Security Hub MFA controls cover IAM users, not role trust policies. |
| IAM-PERM-001 | IAM.1, IAM.21 | IAM.1: not in v5.0.0 (v1.4.0 1.16). IAM.21: none found | AC-2, AC-2(1), AC-3, AC-3(15), AC-3(7), AC-5, AC-6, AC-6(10), AC-6(2), AC-6(3) | **uncertain**, partial | Those controls check customer managed policies. These are inline policies. |
| IAM-TAMPER-001 | none found | none found | **uncertain**: AU-9, AC-6 | related | Reviewer judgment. |
| IAM-SESSION-001 | none found | none found | none | none found | |
| BASE-COMP-001, BASE-SCOPE-001, DISCLAIM-001, PROV-001, UNSUPPORTED-TYPE-001 | none | none | none | none found | Checker integrity rules. |

## Not assessed, with the nearest control

| Not assessed id | Security Hub control | CIS v5.0.0 | NIST SP 800-53 Rev. 5 | Notes |
| --- | --- | --- | --- | --- |
| `s3-object-lock-default-off-and-mfa-delete` | S3.15, S3.20 | S3.20: 2.1.2 | S3.15: CP-6(2). S3.20: CA-9(1), CM-2, CM-2(2), CM-3, SC-5(2) | MFA Delete cannot be used with lifecycle [REVIEW S14]. |
| `s3-server-access-logging` | S3.9, CloudTrail.7 | CloudTrail.7: 3.4 | S3.9: AC-2(4), AC-4(26), AC-6(9), AU-10, AU-12, AU-2, AU-3, AU-6(3), AU-6(4), CA-7, SC-7(9), SI-3(8), SI-4(20), SI-7(8) | |
| `guardduty-securityhub-config-analyzer-macie` | IAM.28, Config.1 | IAM.28: 1.19. Config.1: 3.3 | IAM.28: none listed | Other services in this id are not mapped here. |
| `organization-trail-scope` | none found | none found | none | |
| `other-iam-in-the-account` | KMS.1, KMS.2, IAM.1 | see above | see above | **uncertain** |

## Sources

All read on 13 November 2026.

| Id | Page |
| --- | --- |
| C1 | https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html |
| C2 | https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html |
| C3 | https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html |
| C4 | https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html |
| C5 | https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html |

`REVIEW S1` and `REVIEW S14` refer to the source table in `docs/REVIEW-2026-11-13.md`.

Not read: the CIS Benchmark PDF and NIST SP 800-53 Rev. 5 itself. AU-11 and the other ids marked **uncertain** should be checked against NIST before any public claim.
