# Authorization (RBAC)

Azure RBAC role assignments lite on ARM scopes.

## Status

**lab** — Create/get/list role assignments; built-in Owner / Contributor / Reader role definition IDs recognized by the evaluator.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT` | `/{scope}/providers/Microsoft.Authorization/roleAssignments/{name}` |
| `GET` | `/{scope}/providers/Microsoft.Authorization/roleAssignments/{name}` |
| `GET` | `/{scope}/providers/Microsoft.Authorization/roleAssignments` |

`scope` is typically `/subscriptions/{sub}` or `/subscriptions/{sub}/resourceGroups/{rg}`.

## Authz

- Bearer required
- Role assignment writes require Owner (or root bypass)
- Contributor cannot mutate role assignments

## Detailed actions

- Upsert role assignment with `roleDefinitionId` + `principalId`
- Exact scope match plus parent subscription scope for evaluation
- Deny by default for non-root principals without a grant

## Not implemented

- Custom role definitions CRUD
- Deny assignments
- PIM eligible / active assignment schedules
- Conditional Access integration

## Emulator limits

- Built-in role GUIDs only (Owner / Contributor / Reader)
- Root principal bypasses all RBAC checks (documented in security-defaults)

## Deferred depth

- Full role definition catalogue
- Management group scoped assignments

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
SCOPE="/subscriptions/$SUB"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599$SCOPE/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
```
