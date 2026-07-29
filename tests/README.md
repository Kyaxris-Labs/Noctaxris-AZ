# Integration tests

Real SDK and Terraform suites against a running Noctaxris-AZ API. Soft-skip when the endpoint or root token is unset.

Endpoint default: `http://127.0.0.1:4599`. Use the same root Bearer as `docker/.env` when Compose is present.

## Prerequisites

1. API up and ready (example `docker run` from the root README), or Compose when files are present:

```bash
# docker run path: set ROOT_TOKEN from your run -e values
curl -fsS http://127.0.0.1:4599/_noctaxris-az/health
curl -fsS http://127.0.0.1:4599/_noctaxris-az/ready
```

2. Export credentials:

```bash
export NOCTAXRIS_AZ_ENDPOINT=http://127.0.0.1:4599
export NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
export NOCTAXRIS_AZ_SUBSCRIPTION_ID="${NOCTAXRIS_AZ_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000002}"
```

| Suite | Tools |
|-------|--------|
| SDK (Go) | Go 1.22+ (module under `tests/sdk/go`) |
| SDK (Node.js) | Node.js 24+; `npm install` under `tests/sdk/nodejs` |
| SDK (Python) | Python 3.10+; `pip install -r requirements.txt` under `tests/sdk/python` |
| Terraform | Terraform CLI when stacks exist under `tests/terraform/` |

## Soft-skip vs hard-fail

| Case | Behavior |
|------|----------|
| `NOCTAXRIS_AZ_ENDPOINT` unset inside an SDK/TF test | Soft-skip that test |
| API not ready when running `tests/run-all.sh` | Hard-fail (exit 1) |
| Root token unset when running `tests/run-all.sh` | Hard-fail (exit 1) |

## Run all suites

From the repo root (bash / WSL / Git Bash):

```bash
bash tests/run-all.sh
```

Or run each suite:

```bash
cd tests/sdk/go && go test ./... -count=1 -timeout 10m

cd tests/sdk/nodejs && npm install && npm test

cd tests/sdk/python && pip install -r requirements.txt && pytest
```

## Related

- [HANDOFF.md](HANDOFF.md)
- [docs/ops.md](../docs/ops.md)
- [docs/services/index.md](../docs/services/index.md)
