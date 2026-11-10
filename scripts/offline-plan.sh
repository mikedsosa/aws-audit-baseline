#!/usr/bin/env bash
# Create a local Terraform plan JSON without AWS credentials or apply.
# The script unsets ambient AWS credential variables so they are not sent.
# It does not print the environment.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="${root}/tests/fixtures/generated"
mkdir -p "${out_dir}"
plan_bin="$(mktemp)"
plan_json="${out_dir}/offline.plan.json"

cleanup() {
  rm -f "${plan_bin}"
}
trap cleanup EXIT

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
  AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
  AWS_CONTAINER_CREDENTIALS_FULL_URI || true
export AWS_EC2_METADATA_DISABLED=true

terraform -chdir="${root}/terraform" init -backend=false -input=false
terraform -chdir="${root}/terraform" plan \
  -input=false \
  -lock=false \
  -refresh=false \
  -var-file="${root}/examples/offline.tfvars" \
  -out="${plan_bin}"
terraform -chdir="${root}/terraform" show -json "${plan_bin}" > "${plan_json}"

python3 - "${plan_json}" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
banned = ("AKIA", "ASIA", "aws_secret_access_key", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
for marker in banned:
    if marker in text:
        raise SystemExit(f"refusing to keep plan JSON; found marker {marker}")
print(f"wrote {sys.argv[1]} bytes={len(text.encode('utf-8'))}")
PY
