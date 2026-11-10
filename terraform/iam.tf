resource "aws_iam_role" "workload_operator" {
  name                 = local.workload_role_name
  assume_role_policy   = local.workload_trust_policy
  max_session_duration = 3600

  tags = merge(local.common_tags, {
    BaselineComponent = "workload-operator"
  })
}

resource "aws_iam_role_policy" "workload_operator" {
  name   = "workload-app-prefix"
  role   = aws_iam_role.workload_operator.name
  policy = local.workload_role_policy
}

resource "aws_iam_role" "auditor" {
  name                 = local.auditor_role_name
  assume_role_policy   = local.auditor_trust_policy
  max_session_duration = 3600

  tags = merge(local.common_tags, {
    BaselineComponent = "auditor"
  })
}

resource "aws_iam_role_policy" "auditor" {
  name   = "audit-read"
  role   = aws_iam_role.auditor.name
  policy = local.auditor_role_policy
}
