package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	labActivityInjectPath    = "/_noctaxris-az/lab/activityLog:inject"
	labLogsInjectPath        = "/_noctaxris-az/lab/logs:inject"
	labAssessmentsInjectPath = "/_noctaxris-az/lab/securityAssessments:inject"
	injectMaxEntries         = 50
	injectMaxDepth           = 8
	injectMaxMapKeys         = 64
	injectMaxStrLen          = 1024
)

// MountLab registers env-gated forensic inject routes.
func (h *Handler) MountLab(mux *http.ServeMux, principalFrom principalFunc) {
	mux.HandleFunc("POST "+labActivityInjectPath, h.wrap(principalFrom, h.injectActivityLog))
	mux.HandleFunc("POST "+labLogsInjectPath, h.wrap(principalFrom, h.injectLogRows))
	mux.HandleFunc("POST "+labAssessmentsInjectPath, h.wrap(principalFrom, h.injectAssessments))
}

func (h *Handler) requireInjectRoot(w http.ResponseWriter, p authn.Principal, enabled bool, env, label string) bool {
	if !enabled {
		azerrors.WriteARM(w, http.StatusForbidden, "AccessDenied",
			label+" is disabled. Set "+env+"=1 to enable.")
		return false
	}
	if !p.IsRoot {
		azerrors.WriteARM(w, http.StatusForbidden, "AccessDenied", label+" requires Bearer root")
		return false
	}
	return true
}

type activityInjectReq struct {
	Events []activityInjectEvent `json:"events"`
	Event  *activityInjectEvent  `json:"event"`
}

type activityInjectEvent struct {
	EventTimestamp string          `json:"eventTimestamp"`
	Caller         string          `json:"caller"`
	OperationName  any             `json:"operationName"`
	Status         any             `json:"status"`
	ResourceID     string          `json:"resourceId"`
	CallerIP       string          `json:"callerIpAddress"`
	ClientIP       string          `json:"clientIp"`
	Description    string          `json:"description"`
	Identity       json.RawMessage `json:"identity"`
}

func (h *Handler) injectActivityLog(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	if !h.requireInjectRoot(w, p, h.ActivityInject, "NOCTAXRIS_AZ_ACTIVITY_INJECT", "Activity Log inject") {
		return
	}
	var req activityInjectReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	events := req.Events
	if req.Event != nil {
		events = append(events, *req.Event)
	}
	if len(events) == 0 {
		azerrors.BadRequest(w, "events or event is required")
		return
	}
	if len(events) > injectMaxEntries {
		azerrors.BadRequest(w, "at most 50 events per inject")
		return
	}
	now := h.now()
	for i, e := range events {
		ts := now.Add(time.Duration(i) * time.Millisecond)
		if raw := strings.TrimSpace(e.EventTimestamp); raw != "" {
			parsed, err := parseInjectTime(raw)
			if err != nil {
				azerrors.BadRequest(w, "eventTimestamp must be RFC3339")
				return
			}
			ts = parsed
		}
		op := stringifyNamed(e.OperationName)
		if op == "" {
			azerrors.BadRequest(w, "operationName is required")
			return
		}
		st := stringifyNamed(e.Status)
		if st == "" {
			st = "Succeeded"
		}
		ip := strings.TrimSpace(e.CallerIP)
		if ip == "" {
			ip = strings.TrimSpace(e.ClientIP)
		}
		ident := ""
		if len(e.Identity) > 0 && string(e.Identity) != "null" {
			var m map[string]any
			if err := json.Unmarshal(e.Identity, &m); err != nil {
				azerrors.BadRequest(w, "identity must be a JSON object")
				return
			}
			b, _ := json.Marshal(redactInjectMap(m, injectMaxDepth))
			ident = string(b)
		}
		row := store.ActivityLogRow{
			Timestamp:    ts,
			Caller:       strings.TrimSpace(e.Caller),
			Operation:    op,
			ResourceID:   strings.TrimSpace(e.ResourceID),
			Status:       st,
			Message:      e.Description,
			ClientIP:     ip,
			IdentityJSON: ident,
		}
		if err := h.Store.AppendActivityLogRow(row); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"written": len(events)})
}

type logsInjectReq struct {
	Workspace string           `json:"workspace"`
	Table     string           `json:"table"`
	Rows      []map[string]any `json:"rows"`
	Row       map[string]any   `json:"row"`
}

func (h *Handler) injectLogRows(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	if !h.requireInjectRoot(w, p, h.LogsInject, "NOCTAXRIS_AZ_LOGS_INJECT", "Log Analytics inject") {
		return
	}
	var req logsInjectReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	rows := req.Rows
	if len(req.Row) > 0 {
		rows = append(rows, req.Row)
	}
	if len(rows) == 0 {
		azerrors.BadRequest(w, "rows or row is required")
		return
	}
	if len(rows) > injectMaxEntries {
		azerrors.BadRequest(w, "at most 50 rows per inject")
		return
	}
	table := strings.TrimSpace(req.Table)
	if !store.IsNamedLogAnalyticsTable(table) {
		azerrors.BadRequest(w, "table must be one of "+strings.Join(store.NamedLogAnalyticsTables, ", "))
		return
	}
	ws := workspaceQueryName(req.Workspace)
	if ws == "" {
		ws = store.DefaultLogAnalyticsWorkspace
	}
	now := h.now()
	for i, row := range rows {
		if row == nil {
			row = map[string]any{}
		}
		if _, ok := row["TimeGenerated"]; !ok {
			row["TimeGenerated"] = now.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano)
		}
		redacted := redactInjectMap(row, injectMaxDepth)
		if err := h.Store.InsertLogAnalyticsRow(ws, table, redacted); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"written": len(rows), "table": table, "workspace": ws})
}

type assessmentsInjectReq struct {
	Assessments    []map[string]any `json:"assessments"`
	Subassessments []map[string]any `json:"subassessments"`
}

func (h *Handler) injectAssessments(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	if !h.requireInjectRoot(w, p, h.DefenderInject, "NOCTAXRIS_AZ_DEFENDER_INJECT", "Defender assessment inject") {
		return
	}
	var req assessmentsInjectReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	items := append([]map[string]any{}, req.Assessments...)
	items = append(items, req.Subassessments...)
	if len(items) == 0 {
		azerrors.BadRequest(w, "assessments or subassessments is required")
		return
	}
	if len(items) > injectMaxEntries {
		azerrors.BadRequest(w, "at most 50 assessments per inject")
		return
	}
	sub := strings.TrimSpace(h.SubscriptionID)
	tenant := strings.TrimSpace(h.TenantID)
	written := 0
	for i, item := range items {
		id := mapString(item, "id")
		name := mapString(item, "name")
		typ := mapString(item, "type")
		if typ == "" {
			if len(req.Subassessments) > 0 && i >= len(req.Assessments) {
				typ = "microsoft.security/assessments/subassessments"
			} else {
				typ = "microsoft.security/assessments"
			}
		}
		if name == "" {
			name = fmt.Sprintf("lab-assessment-%d", i+1)
		}
		if id == "" {
			id = "/subscriptions/" + sub + "/providers/Microsoft.Security/assessments/" + name
			if strings.Contains(strings.ToLower(typ), "subassessment") {
				id = "/subscriptions/" + sub + "/providers/Microsoft.Security/assessments/parent/subassessments/" + name
			}
		}
		rg := mapString(item, "resourceGroup")
		itemSub := mapString(item, "subscriptionId")
		if itemSub == "" {
			itemSub = sub
		}
		props := item["properties"]
		if props == nil {
			props = map[string]any{
				"status": map[string]any{"code": "Unhealthy"},
			}
		}
		if pm, ok := props.(map[string]any); ok {
			props = redactInjectMap(pm, injectMaxDepth)
		}
		b, _ := json.Marshal(props)
		if err := h.Store.UpsertARGResource(id, "SecurityResources", typ, name, itemSub, rg, tenant, string(b)); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		written++
	}
	writeJSON(w, http.StatusOK, map[string]any{"written": written})
}

func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func stringifyNamed(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		if s, ok := t["value"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func parseInjectTime(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, raw)
}

func requestClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func injectSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "password", "secret", "token", "secretstring", "secretbinary",
		"sessiontoken", "idtoken", "accesstoken", "refreshtoken",
		"clientsecret", "privatekey", "credentials", "authorization":
		return true
	}
	if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.HasSuffix(k, "token") {
		return true
	}
	return false
}

func redactInjectMap(m map[string]any, depth int) map[string]any {
	if m == nil {
		return nil
	}
	if depth <= 0 {
		return map[string]any{"_redacted": "depth"}
	}
	out := make(map[string]any)
	count := 0
	for k, v := range m {
		if count >= injectMaxMapKeys {
			out["_truncated"] = true
			break
		}
		count++
		if injectSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = redactInjectValue(v, depth-1)
	}
	return out
}

func redactInjectValue(v any, depth int) any {
	if depth <= 0 {
		return "[redacted:depth]"
	}
	switch t := v.(type) {
	case map[string]any:
		return redactInjectMap(t, depth)
	case []any:
		n := len(t)
		if n > injectMaxMapKeys {
			n = injectMaxMapKeys
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, redactInjectValue(t[i], depth-1))
		}
		return out
	case string:
		if len(t) > injectMaxStrLen {
			return t[:injectMaxStrLen] + "..."
		}
		return t
	default:
		return t
	}
}
