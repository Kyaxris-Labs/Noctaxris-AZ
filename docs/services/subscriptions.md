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

ARG `POST /providers/Microsoft.ResourceGraph/resources` evaluates `Microsoft.ResourceGraph/resources/read` at each requested `/subscriptions/{id}` (the lab subscription when the body omits `subscriptions`). Subscription Reader is allowed. A principal with no grant on those subscriptions is HTTP 403. Rows are filtered to authorized subscription ids.

`arm_lab_resources.provider` stores the full ARM type. Subscription-scope LISTs query that value (prefix match `provider = ? OR provider LIKE ? || '/%'`). Unseeded types such as Automation accounts return `"value": []`.

`GET .../Microsoft.Web/sites` also includes Function Apps from the functions table (`kind` `functionapp`) when those rows exist.

## Authz

- Bearer required. Token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- `GET /subscriptions` evaluates `Microsoft.Resources/subscriptions/read` per row and returns HTTP 200 with only visible subscriptions (possibly empty). No grant is not HTTP 403 on the list route.
- `GET .../resourceGroups` evaluates `Microsoft.Resources/subscriptions/resourceGroups/read` per group (subscription-scope grants surface every group via scope walk-up; group-scoped Reader sees only that group) and returns HTTP 200 with the filtered list (possibly empty). No grant is not HTTP 403 on the list route.
- `Microsoft.Resources/subscriptions/read` (get and list filter)
- `Microsoft.Resources/subscriptions/resourceGroups/read|write`
- `Microsoft.Resources/tenants/read`
- `Microsoft.Management/managementGroups/read` (descendants authorize `/providers/Microsoft.Management/managementGroups/{id}`)
- `Microsoft.ResourceGraph/resources/read`
- Provider reads use `Microsoft.Resources/resources/read` or the provider action (Storage, Web, Authorization)

## Detailed actions

- List and get subscription display name / state / tenant (list is RBAC-filtered)
- List tenants (lab tenant from the seeded subscription)
- List management groups and descendants (direct child groups, plus same-tenant subscriptions under the tenant-root group). Unknown `{id}` returns 404.
- Upsert and get resource group location
- List resource groups in a subscription (RBAC-filtered per group)
- ARG query over stored `arg_resources` rows (`Resources` and `SecurityResources`; Defender inject writes assessments into `SecurityResources`)
- Subscription-scope inventory for VMs, Key Vault, Storage, Web sites, ACR, AKS, Logic Apps (role assignment list is [authorization.md](authorization.md))

## Standalone subscription

`NOCTAXRIS_AZ_LAB_STANDALONE` defaults off. `POST /_noctaxris-az/lab/subscriptions:seedStandalone` is then HTTP 404 before authentication and is not a public route. With the flag on, the route runs after bearer authentication and accepts only the root token.

The body is `{"name":"<seed>"}`. An empty name uses `default`. The same name returns the same access token and subscription id. A different name creates another subscription.

The seed stays in the configured tenant. It adds one directory user (not the seeded lab admin) and one Owner assignment at `/subscriptions/{newId}` only. Principal type is User. There is no directory role and the root client is not the assignee. The access token audience is `https://management.azure.com`, `tid` is the configured tenant, and `oid` is the new user, so the token is not root. `GET /subscriptions` with that token lists only that subscription. Reading the lab subscription, or a resource group in it, is denied. Blob data-plane calls and Key Vault `getSecret` stay on their existing handlers and are denied for this token. Directory reads are not part of this route. Those rules are in [entra.md](entra.md).

## Not implemented

- ARM subscription create/delete / move (the standalone route above is an ops seed, not `PUT /subscriptions/{id}`)
- Full provider registration / feature registration catalogue
- ARG KQL engine beyond table name, `type ==`, and `limit`

## Emulator limits

- Default subscription id: `NOCTAXRIS_AZ_SUBSCRIPTION_ID`
- Standalone subscriptions use the same configured tenant. A second directory tenant is not issued.
- Empty `value` arrays for types with no stored rows (not HTTP 500)

## Deferred depth

- Deployment history / ARM template engines beyond sibling products
- Cost Management / Billing
- Live `az graph query` / AzureHound ARM smokes (soft-skip when the CLI is missing)

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=${NOCTAXRIS_AZ_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000002}
BASE="${NOCTAXRIS_AZ_PUBLIC_URL:-https://127.0.0.1:4599}"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" \
  "$BASE/subscriptions?api-version=2022-12-01"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" \
  "$BASE/subscriptions/$SUB?api-version=2022-12-01"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" \
  "$BASE/tenants?api-version=2022-12-01"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" \
  "$BASE/providers/Microsoft.Management/managementGroups/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/descendants?api-version=2020-05-01"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" -X POST \
  -H "Content-Type: application/json" \
  -d '{"subscriptions":["'"$SUB"'"],"query":"Resources"}' \
  "$BASE/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
curl -s --cacert lab-ca.pem -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus"}' \
  "$BASE/subscriptions/$SUB/resourcegroups/rg1?api-version=2022-09-01"
```
