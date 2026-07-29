# Terraform against Noctaxris-AZ

Soft-skips when `NOCTAXRIS_AZ_ENDPOINT` is unset, terraform is missing,
`NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN` is unset, or `/_noctaxris-az/ready` fails.

```bash
export NOCTAXRIS_AZ_ENDPOINT=http://127.0.0.1:4599
export NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN="$ROOT_TOKEN"
bash tests/terraform/run.sh
```

On Windows without bash, soft-skip is the default when the endpoint is unset.

## Stacks

| Dir | Intent |
|-----|--------|
| `storage-account` | `azurerm_storage_account` + table against lab endpoint |
| `managed-identity` | `azurerm_user_assigned_identity` against lab endpoint |

Providers may require HTTPS metadata discovery; optional lab TLS via
`NOCTAXRIS_AZ_TLS_CERT` / `NOCTAXRIS_AZ_TLS_KEY` (see [ops.md](../../docs/ops.md)).
