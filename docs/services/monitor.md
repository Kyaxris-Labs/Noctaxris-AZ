# Monitor / Activity Log / Log Analytics

Activity Log list shaped like Microsoft.Insights eventtypes, metrics write/list theatre, diagnostic settings ARM CRUD lite, and a Log Analytics KQL subset. Lab inject and clock routes are env-gated and default off.

## Status

**lab.** List Activity Log values; POST/GET metrics samples; workspace ARM; KQL `take` / `where ==` / `TimeGenerated` range / `project`; diagnostic settings store (no export pipeline). Other packages may call `AppendActivity` / `AppendActivityLogRow` after ARM mutations.

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values` |
| `POST` | `/subscriptions/{sub}/providers/Microsoft.Insights/metrics` |
| `GET` | `/subscriptions/{sub}/providers/Microsoft.Insights/metrics` |
| `PUT` / `GET` / `DELETE` | `/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings/{name}` |
| `GET` | `/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings` |
| `PUT` / `GET` / `DELETE` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{rtype}/{res}/providers/Microsoft.Insights/diagnosticSettings/{name}` |
| `GET` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{rtype}/{res}/providers/Microsoft.Insights/diagnosticSettings` |
| `PUT` / `GET` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}` |
| `POST` | `/loganalytics/{workspace}/query` |
| `POST` | `/loganalytics/{workspace}/ingest/{table}` |
| `POST` | `/_noctaxris-az/lab/clock:freeze` / `:unfreeze` / `:set` |
| `POST` | `/_noctaxris-az/lab/bulkSeed` |
| `POST` | `/_noctaxris-az/lab/activityLog:inject` |
| `POST` | `/_noctaxris-az/lab/logs:inject` |
| `POST` | `/_noctaxris-az/lab/securityAssessments:inject` |

Activity Log supports `$top`. List returns events whose `resourceId` is `/subscriptions/{sub}` or a child of that subscription. `subscriptionId` on each event is the path subscription.

Metrics POST body: `{"name","value","resourceId"}`. Metrics GET accepts `metricnames` or `name`.

Diagnostic settings follow ARM `Microsoft.Insights/diagnosticSettings` with api-version `2021-05-01-preview`. PUT body properties used: `workspaceId`, `storageAccountId`, `eventHubAuthorizationRuleId`, `eventHubName`, `logs[]`, `metrics[]`. Nested resource paths cover one provider/type/name segment (not child resources such as `blobServices`). Settings are stored; logs and metrics are not shipped to a workspace, storage account, or Event Hub.

### Lab clock and BulkSeed (`NOCTAXRIS_AZ_LAB_FORENSICS`)

In-memory on the HTTP server (`clockMu` / `clockOverride`). Not SQLite. Default off returns AccessDenied. Bearer root required.

| Route | Body | Result |
|-------|------|--------|
| `POST /_noctaxris-az/lab/clock:freeze` | `{}` | Pin current lab time |
| `POST /_noctaxris-az/lab/clock:set` | `{"fixedTime":"<RFC3339>"}` | Pin that instant (`clockTime` accepted as alias) |
| `POST /_noctaxris-az/lab/clock:unfreeze` | `{}` | Resume wall clock |
| `POST /_noctaxris-az/lab/bulkSeed` | `{"scenarioId":"..."}` | Seed Activity Log, named LA rows, and ARG assessments |

BulkSeed `scenarioId` values: `suspicious-signin`, `blob-exfil`, `crypto-mining`. Optional `subscriptionId` defaults to `NOCTAXRIS_AZ_SUBSCRIPTION_ID`. Inject timestamps without an explicit time use the lab clock. Bearer token expiry stays wall clock. Restart clears the override.

### Inject (default off, Bearer root, cap 50)

| Env | Route | Destination |
|-----|-------|-------------|
| `NOCTAXRIS_AZ_ACTIVITY_INJECT` | `POST /_noctaxris-az/lab/activityLog:inject` | Same `activity_log` rows as `GET .../eventtypes/management/values` / `az monitor activity-log` |
| `NOCTAXRIS_AZ_LOGS_INJECT` | `POST /_noctaxris-az/lab/logs:inject` and `POST /loganalytics/{workspace}/ingest/{table}` | Named Log Analytics tables (and any table name on the ingest route) |
| `NOCTAXRIS_AZ_DEFENDER_INJECT` | `POST /_noctaxris-az/lab/securityAssessments:inject` | ARG `SecurityResources` (`microsoft.security/assessments` and `.../subassessments`) |

Activity inject fields: `eventTimestamp`, `caller`, `operationName`, `status`, `resourceId`, `callerIpAddress` / `clientIp`, `identity`. List output includes `callerIpAddress`, `httpRequest.clientIpAddress`, and parsed `identity` when present. Client IP is taken from the TCP peer (`RemoteAddr`). Forwarded headers are ignored.

Log inject body: `{"workspace":"default","table":"<named>","rows":[{...}]}`. Missing `TimeGenerated` is filled from the lab clock. Named tables: `ApiManagementGatewayLogs`, `AADManagedIdentitySignInLogs`, `AADServicePrincipalSignInLogs`, `AzureActivity`, `ContainerAppSystemLogs`, `DataPlaneRequests`, `ContainerRegistryRepositoryEvents`.

Assessment inject body: `{"assessments":[{...}],"subassessments":[{...}]}`. Properties follow Defender ARG shape (`properties.status.code` such as `Unhealthy`, `properties.resourceDetails` with `Source` / `Id`). Query those rows with ARG `SecurityResources` (see [subscriptions.md](subscriptions.md)).

Secret-like JSON keys (`password`, `secret`, `token`, `authorization`, and names containing those) are replaced with `[REDACTED]` next to the inject handlers.

### KQL subset

`POST /loganalytics/{workspace}/query` with `{"query":"..."}`. Supported operators on stored columns:

| Operator | Behavior |
|----------|----------|
| `Table \| take N` | First N ingested rows |
| `where Col == 'x'` | Exact string match |
| `where TimeGenerated >= datetime('...')` | RFC3339 range (`>=`, `<=`, `>`, `<`, `==`) |
| `project ColA, ColB` | Keep listed keys |

This is not Azure Monitor KQL. Joins, `ago()`, `summarize`, `extend`, and the rest of the language are not implemented.

## Authz

- Bearer required. Token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- `Microsoft.Insights/eventtypes/values/read`
- `Microsoft.Insights/metrics/read` and `.../write`
- `Microsoft.Insights/diagnosticSettings/read`, `.../write`, `.../delete`
- `Microsoft.OperationalInsights/workspaces/read`, `.../write`, and `.../query/action`
- Lab inject, clock, BulkSeed, and `POST /loganalytics/{workspace}/ingest/{table}`: env flag plus Bearer root (not RBAC). Ingest is off unless `NOCTAXRIS_AZ_LOGS_INJECT=1`.

## Detailed actions

- List recent activity rows for the path subscription (`eventTimestamp`, `caller`, `operationName`, `status`, `resourceId`, client IP, `identity`)
- Write a metric sample and list samples as timeseries theatre
- PUT/GET/DELETE/LIST diagnostic settings; PUT and DELETE append Activity Log
- Ingest JSON rows (`NOCTAXRIS_AZ_LOGS_INJECT` plus Bearer root) and query the KQL subset
- Env-gated inject and BulkSeed for forensic labs

Live mutations already appending Activity Log keep doing so (resource group write, diagnostic settings write/delete). Entra client-credentials and IMDS token mint append sign-in rows to `AADServicePrincipalSignInLogs` / `AADManagedIdentitySignInLogs` on workspace `default` (redacted metadata, not secrets). See [entra.md](entra.md) and [managedidentity.md](managedidentity.md).

## Not implemented

- Diagnostic settings delivery to Storage / Event Hub / Log Analytics (CRUD only)
- Alert rules evaluation and action groups
- Full Metrics batch API / metric definitions catalogue
- Application Insights SDK ingest
- Full Azure Monitor KQL

## Emulator limits

- Activity Log is SQLite append-only theatre, listed per path subscription (`resourceId` prefix)
- Metrics are simple name/value samples
- Diagnostic settings persist `workspaceId` / `logs` / `metrics` JSON and do not forward
- Lab clock is process memory
- Nested diagnostic setting ARM ids stop at one resource name segment

## Deferred depth

- Export pipeline (workspace / storage / Event Hub)
- Autoscale / scheduled query rules
- Broader KQL (`ago`, `summarize`, joins)

## Verification / CLI smoke

```bash
go test ./internal/services/monitor/ -count=1
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H "Content-Type: application/json" \
  -d '{"properties":{"workspaceId":"/subscriptions/'"$SUB"'/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1","logs":[{"category":"AuditEvent","enabled":true}],"metrics":[{"category":"AllMetrics","enabled":true}]}}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1/providers/Microsoft.Insights/diagnosticSettings/to-la?api-version=2021-05-01-preview"
curl -s -H "Authorization: Bearer $TOKEN" -X POST -H "Content-Type: application/json" \
  -d '{"query":"AzureActivity | take 5"}' \
  "http://127.0.0.1:4599/loganalytics/default/query"
```

Clock and inject routes return AccessDenied unless the matching `NOCTAXRIS_AZ_*` flag is set and the caller is Bearer root. Live Azure CLI / Az PowerShell / `prowler` runs soft-skip when `az` or `pwsh` is missing (see [tests/README.md](../../tests/README.md)). Those live runs are not executed in this cut.
