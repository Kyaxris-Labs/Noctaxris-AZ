#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ -z "${NOCTAXRIS_AZ_ENDPOINT:-}" ]]; then
  echo "NOCTAXRIS_AZ_ENDPOINT unset — soft-skip Terraform suite"
  exit 0
fi
if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform not installed — soft-skip"
  exit 0
fi
if [[ -z "${NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN:-}" ]]; then
  echo "NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN unset — soft-skip"
  exit 0
fi
ready_code="$(curl -s -o /dev/null -w '%{http_code}' "${NOCTAXRIS_AZ_ENDPOINT%/}/_noctaxris-az/ready" || true)"
if [[ "$ready_code" != "200" ]]; then
  echo "API not ready at ${NOCTAXRIS_AZ_ENDPOINT} — soft-skip"
  exit 0
fi
for stack in storage-account managed-identity; do
  echo "== terraform soft-check $stack =="
  (cd "$ROOT/$stack" && terraform init -backend=false -input=false >/dev/null && terraform validate)
done
echo "Terraform soft-check OK (validate only; apply is operator-driven)"
