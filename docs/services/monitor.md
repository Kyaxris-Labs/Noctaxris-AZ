# Monitor / Activity Log

Activity Log list shaped like Microsoft.Insights eventtypes, plus metrics write/list theatre.

## Status

**lab** — List Activity Log values; POST/GET metrics samples. Other packages may call `AppendActivity` / `AppendActivityLog` after ARM mutations.

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values` |
| `POST` | `/subscriptions/{sub}/providers/Microsoft.Insights/metrics` |
| `GET` | `/subscriptions/{sub}/providers/Microsoft.Insights/metrics` |

Activity Log supports `$top`. Metrics POST body: `{"name","value","resourceId"}`. Metrics GET accepts `metricnames` or `name`.

## Authz

- `Microsoft.Insights/eventtypes/values/read`
- `Microsoft.Insights/metrics/read|write`

## Detailed actions

- List recent activity rows (`eventTimestamp`, `caller`, `operationName`, `status`, `resourceId`)
- Write a metric sample
- List metric samples as timeseries theatre

## Not implemented

- Diagnostic settings delivery to Storage / Event Hub / Log Analytics
- Alert rules evaluation and action groups
- Full Metrics batch API / metric definitions catalogue
- Application Insights SDK ingest

## Emulator limits

- Activity Log is SQLite append-only theatre (not Azure Monitor Logs KQL)
- Metrics are simple name/value samples

## Deferred depth

- Log Analytics workspace + KQL
- Autoscale / scheduled query rules

## Verification / CLI smoke

```bash
go test ./internal/services/monitor/ -count=1
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
curl -s -H "Authorization: Bearer $TOKEN" -X POST -H "Content-Type: application/json" \
  -d '{"name":"Requests","value":1,"resourceId":"/subscriptions/'"$SUB"'"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/providers/Microsoft.Insights/metrics"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/providers/Microsoft.Insights/metrics?metricnames=Requests"
```
