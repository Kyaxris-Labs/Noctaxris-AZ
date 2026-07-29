# Managed Identity

User-assigned Managed Identity ARM lite plus IMDS token theatre on the lab listener.

## Status

**lab** — User-assigned identity CRUD/list; `GET /metadata/identity/oauth2/token` mints lab JWTs via Entra signing material.

## Wire protocol

| Surface | Path |
|---------|------|
| ARM identity | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}` |
| List | `GET .../userAssignedIdentities` |
| IMDS theatre | `GET /metadata/identity/oauth2/token?api-version=...&resource=...&client_id=...` |

IMDS is public (no Bearer). `Metadata: true` (exact lowercase) is required, plus
`api-version` (>= `2018-02-01`) and `resource`. Optional `client_id` / `object_id`.
Tokens are RS256 lab JWTs accepted as ARM Bearer. Response fields follow the
IMDS shape (`expires_in`/`expires_on`/`not_before` as strings).

Lab path is on the API listener (not a real link-local `169.254.169.254`).

## Authz / authn

- ARM routes: Bearer + RBAC (`Microsoft.ManagedIdentity/...`)
- IMDS: unauthenticated lab path on the API listener (not a real link-local `169.254.169.254` interface)

## Detailed actions

- Create / get / delete / list user-assigned identities
- Mint access token for a `resource` audience, optionally scoped by `client_id`

## Not implemented

- System-assigned identities on compute resources
- Federated identity credentials / workload identity federation
- Real host IMDS binding to `169.254.169.254`

## Emulator limits

- IMDS lives on the same loopback HTTP port as ARM (documented theatre path)
- Soft-delete / recover not applicable

## Deferred depth

- Attach identities to VMs / Function Apps / Container Apps when those surfaces deepen

## Verification / CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -X PUT \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1?api-version=2023-01-31" \
  -d '{"location":"eastus"}'
curl -H "Metadata: true" \
  "http://127.0.0.1:4599/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```
