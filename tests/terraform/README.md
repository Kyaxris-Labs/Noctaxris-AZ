# Terraform against Noctaxris-AZ

Soft-skips when `NOCTAXRIS_AZ_ENDPOINT` is unset, terraform is missing,
`NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN` is unset, or `/_noctaxris-az/ready` fails.

```bash
export NOCTAXRIS_AZ_ENDPOINT=http://127.0.0.1:4599
export NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN="$ROOT_TOKEN"
# When stacks and run.sh exist:
# bash tests/terraform/run.sh
```

On Windows without bash, soft-skip is the default when the endpoint is unset.
With Git Bash or WSL, use the same bash runner path when present. PowerShell
can only soft-skip today (no native runner):

```powershell
if (-not $env:NOCTAXRIS_AZ_ENDPOINT) { Write-Host "NOCTAXRIS_AZ_ENDPOINT unset — skip Terraform suite" }
```

## Stacks

No default stacks yet. Add ARM-shaped Terraform projects here as providers gain
custom endpoint coverage against the lab.
