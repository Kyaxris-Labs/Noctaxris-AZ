# Authorization (RBAC)

Azure RBAC role assignments lite on ARM scopes.

## Status

**lab.** Create, get, list, and delete role assignments. The evaluator expands Entra group members and honors stored built-in role GUIDs, not only Owner / Contributor / Reader names.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT` | `/{scope}/providers/Microsoft.Authorization/roleAssignments/{name}` |
| `GET` | `/{scope}/providers/Microsoft.Authorization/roleAssignments/{name}` |
| `DELETE` | `/{scope}/providers/Microsoft.Authorization/roleAssignments/{name}` |
| `GET` | `/{scope}/providers/Microsoft.Authorization/roleAssignments` |

`scope` is typically `/subscriptions/{sub}` or `/subscriptions/{sub}/resourceGroups/{rg}`. `api-version` is required.

## Authz

- Bearer required. Token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- Role assignment writes and deletes require Owner (or root bypass). Contributor cannot mutate role assignments.
- A user in a group that holds Reader on a resource group is authorized as that member. A principal that is not a member is HTTP 403.

## Detailed actions

- Upsert role assignment with `roleDefinitionId` + `principalId`
- Delete a role assignment (HTTP 200 with the deleted body). Appends Activity Log `Microsoft.Authorization/roleAssignments/delete`
- List role assignments by subscription or resource group scope prefix
- Exact scope match for each ancestor in the ARM scope chain (sibling resource group names do not share a prefix)
- Role definition IDs match built-in GUIDs (or the full roleDefinitions path). Display-name substrings such as `owner` are not Owner.
- Group principal assignments expand `entra_group_members` (nested groups, depth cap 8)
- Deny by default for non-root principals without a grant

Built-in GUIDs the evaluator maps (full `/providers/Microsoft.Authorization/roleDefinitions/{guid}` or the guid alone):

| Role | GUID | Lab grant |
|------|------|-----------|
| Owner | `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` | all actions |
| Contributor | `b24988ac-6180-42a0-ab88-20f7382dd24c` | all except roleAssignments mutate |
| Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` | ARM `*/read` and Resource Graph read. Not workspace KQL. |
| Log Analytics Reader | `73c42c96-874c-492b-b04d-ab87d138a893` (also `73c42c96-874c-492b-b04d-ab87d988a1e9`) | ARM `*/read` plus workspace `query/read` and `query/action` |
| Monitoring Reader | `43d0d8ad-25c7-4714-9337-8ba259a9fe05` | ARM `*/read`. Not workspace KQL. |
| Log Analytics Data Reader | `3b03c2da-16b3-4a49-8834-0f8130efdd3b` | workspace read/query only |
| AcrPull | `7f951dda-4ed3-4680-a7ca-43fe172d538d` | `Microsoft.ContainerRegistry/registries` read/pull. Registry V2 pull on `/v2/`; push denied |
| Azure Event Hubs Data Owner | `f526a384-b230-433a-b45c-95f59c4a2dec` (alias `f526a384-b744-4348-a86b-d3d1f7ce3260`) | Event Hubs send/receive/read data plane (not ARM namespace write) |
| Azure Event Hubs Data Receiver | `a638d3c7-ab3a-418d-83e6-5f17a39d4fde` (alias `a638d3c7-ad44-4d07-a2c2-6d98be95d4e5`) | Event Hubs receive data plane |
| Key Vault Secrets Officer | `b86a8fe4-44ce-4948-aee5-eccb2c155cd7` | Key Vault secrets get/set/delete/recover (not keys or certificates) |
| Key Vault Secrets User | `4633458b-17de-408a-b874-0445c86b69e6` | Key Vault secrets get |
| Key Vault Administrator | `00482a5a-887f-4fb3-b363-3b7fe8e74483` | Key Vault data-plane administration |

## Not implemented

- Custom role definitions CRUD
- Deny assignments
- PIM eligible / active assignment schedules
- Conditional Access integration

## Emulator limits

- Built-in GUIDs listed above. Unknown role definition IDs deny.
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
