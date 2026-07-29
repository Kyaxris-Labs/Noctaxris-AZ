#!/usr/bin/env bash
# Run SDK and Terraform integration suites against Noctaxris-AZ.
#
# Soft-skip: individual SDK/TF tests skip when endpoint/token/ready fail.
# Hard-fail: this script exits non-zero if the API is not ready or root token
# is missing (suites cannot run at all).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export NOCTAXRIS_AZ_ENDPOINT="${NOCTAXRIS_AZ_ENDPOINT:-http://127.0.0.1:4599}"
export NOCTAXRIS_AZ_SUBSCRIPTION_ID="${NOCTAXRIS_AZ_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000002}"

EP="$NOCTAXRIS_AZ_ENDPOINT"
if ! curl -fsS "$EP/_noctaxris-az/ready" >/dev/null; then
  echo "Noctaxris-AZ not ready at $EP — start the API first (see tests/README.md)" >&2
  echo "Hard-fail: API readiness required for run-all (not a soft-skip)." >&2
  exit 1
fi

if [[ -z "${NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN:-}" ]]; then
  if [[ -f docker/.env ]]; then
    # shellcheck disable=SC1091
    set -a && source docker/.env && set +a
  fi
fi
if [[ -z "${NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN:-}" ]]; then
  echo "NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN unset — export it or source docker/.env" >&2
  echo "Hard-fail: root token required for run-all (not a soft-skip)." >&2
  exit 1
fi

echo "==> SDK (Go)"
(cd tests/sdk/go && go test ./... -count=1 -timeout 10m)

echo "==> SDK (Node.js)"
(cd tests/sdk/nodejs && npm install --no-fund --no-audit && npm test)

echo "==> SDK (Python)"
(cd tests/sdk/python && python -m pip install -q -r requirements.txt && python -m pytest)

if [[ -f tests/terraform/run.sh ]]; then
  echo "==> Terraform"
  bash tests/terraform/run.sh
else
  echo "==> Terraform (no run.sh yet; soft-skip)"
fi

echo "All suites finished."
