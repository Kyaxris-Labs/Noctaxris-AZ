# Subscriptions and resource groups

ARM subscription get and resource group CRUD lite.

## Status

**lab** — Seeded subscription from EnsureRoot; resource groups create/get/list.

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/subscriptions/{subscriptionId}` |
| `GET` | `/subscriptions/{subscriptionId}/resourcegroups` |
| `PUT` | `/subscriptions/{subscriptionId}/resourcegroups/{rg}` |
| `GET` | `/subscriptions/{subscriptionId}/resourcegroups/{rg}` |

Query `api-version` is accepted and ignored for routing.

## Authz

- Bearer required
- `Microsoft.Resources/subscriptions/read`
- `Microsoft.Resources/subscriptions/resourceGroups/read|write`

## Detailed actions

- Get subscription display name / state / tenant
- Upsert and get resource group location
- List resource groups in a subscription

## Not implemented

- Subscription create/delete / move
- Management groups
- Tags beyond stored JSON theatre when present
- Provider registration catalogue

## Emulator limits

- Default subscription id: `NOCTAXRIS_AZ_SUBSCRIPTION_ID`
- Single-tenant lab seed only

## Deferred depth

- Deployment history / ARM template engines beyond sibling products
- Cost Management / Billing

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB?api-version=2022-12-01"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1?api-version=2022-09-01"
```
