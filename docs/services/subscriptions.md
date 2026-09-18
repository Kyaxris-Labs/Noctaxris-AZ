# Subscriptions and resource groups

ARM subscription list/get, tenants, management groups, Azure Resource Graph, and subscription-scope provider LISTs.

## Status

**lab.** Seeded subscription from EnsureRoot; `GET /subscriptions` list and `GET /subscriptions/{id}` get; resource groups; ARG `Resources` and `SecurityResources`; provider LISTs keyed by full ARM type (for example `Microsoft.Compute/virtualMachines`).

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/subscriptions` |
| `GET` | `/subscriptions/{subscriptionId}` |
| `GET` | `/tenants` |
| `GET` | `/providers/Microsoft.Management/managementGroups` |
| `GET` | `/providers/Microsoft.Management/managementGroups/{id}/descendants` |
| `POST` | `/providers/Microsoft.ResourceGraph/resources` |
| `GET` | `/subscriptions/{subscriptionId}/resources` |
| `GET` | `/subscriptions/{subscriptionId}/providers` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.Web/sites` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.Logic/workflows` |
| `GET` | `/subscriptions/{subscriptionId}/providers/Microsoft.Automation/automationAccounts` |
| `GET` | `/subscriptions/{subscriptionId}/resourcegroups` |
| `PUT` | `/subscriptions/{subscriptionId}/resourcegroups/{rg}` |
| `GET` | `/subscriptions/{subscriptionId}/resourcegroups/{rg}` |

Query `api-version` is required on these ARM routes.

`GET .../managementGroups/{id}/descendants` loads that group (404 if missing or in another tenant) and returns only its direct children. Subscriptions are listed for the tenant-root group (`parent_id` empty) in the same `tenant_id`. A bogus `{id}` does not dump every subscription.

ARG body: `{"subscriptions":["..."],"query":"..."}`. Tables `Resources` and `SecurityResources` are recognized in the query text. Response fields: `totalRecords`, `count`, `data`, `resultTruncated`.

`arm_lab_resources.provider` stores the full ARM type. Subscription-scope LISTs query that value (prefix match `provider = ? OR provider LIKE ? || '/%'`). Unseeded types such as Automation accounts return `"value": []`.

`GET .../Microsoft.Web/sites` also includes Function Apps from the functions table (`kind` `functionapp`) when those rows exist.

## Authz

- Bearer required. Token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- `Microsoft.Resources/subscriptions/read`
- `Microsoft.Resources/subscriptions/resourceGroups/read|write`
- `Microsoft.Resources/tenants/read`
- `Microsoft.Management/managementGroups/read` (descendants authorize `/providers/Microsoft.Management/managementGroups/{id}`)
- `Microsoft.ResourceGraph/resources/read`
- Provider reads use `Microsoft.Resources/resources/read` or the provider action (Storage, Web, Authorization)

## Detailed actions

- List and get subscription display name / state / tenant
- List tenants (lab tenant from the seeded subscription)
- List management groups and descendants (direct child groups, plus same-tenant subscriptions under the tenant-root group). Unknown `{id}` returns 404.
- Upsert and get resource group location
- List resource groups in a subscription
- ARG query over stored `arg_resources` rows (`Resources` and `SecurityResources`; Defender inject writes assessments into `SecurityResources`)
- Subscription-scope inventory for VMs, Key Vault, Storage, Web sites, ACR, AKS, Logic Apps (role assignment list is [authorization.md](authorization.md))

## Not implemented

- Subscription create/delete / move
- Full provider registration / feature registration catalogue
- ARG KQL engine beyond table name, `type ==`, and `limit`

## Emulator limits

- Default subscription id: `NOCTAXRIS_AZ_SUBSCRIPTION_ID`
- Single-tenant lab seed only
- Empty `value` arrays for types with no stored rows (not HTTP 500)

## Deferred depth

- Deployment history / ARM template engines beyond sibling products
- Cost Management / Billing
- Live `az graph query` / AzureHound ARM smokes (soft-skip when the CLI is missing)

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=${NOCTAXRIS_AZ_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000002}
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions?api-version=2022-12-01"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB?api-version=2022-12-01"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/tenants?api-version=2022-12-01"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/providers/Microsoft.Management/managementGroups/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/descendants?api-version=2020-05-01"
curl -s -H "Authorization: Bearer $TOKEN" -X POST \
  -H "Content-Type: application/json" \
  -d '{"subscriptions":["'"$SUB"'"],"query":"Resources"}' \
  "http://127.0.0.1:4599/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1?api-version=2022-09-01"
```
