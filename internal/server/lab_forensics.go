package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	labClockFreezePath   = "/_noctaxris-az/lab/clock:freeze"
	labClockUnfreezePath = "/_noctaxris-az/lab/clock:unfreeze"
	labClockSetPath      = "/_noctaxris-az/lab/clock:set"
	labBulkSeedPath      = "/_noctaxris-az/lab/bulkSeed"
)

func (s *Server) effectiveNow() time.Time {
	s.clockMu.RLock()
	defer s.clockMu.RUnlock()
	return s.labClockNowLocked()
}

// authClock is wall time for Bearer expiry (lab clock must not affect auth).
func (s *Server) authClock() time.Time {
	return time.Now().UTC()
}

func (s *Server) labClockNowLocked() time.Time {
	if s.clockOverride != nil {
		return s.clockOverride.UTC()
	}
	return time.Now().UTC()
}

func (s *Server) freezeLabClock() time.Time {
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	t := s.labClockNowLocked()
	s.clockOverride = &t
	return t
}

func (s *Server) setLabClock(t time.Time) time.Time {
	utc := t.UTC()
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	s.clockOverride = &utc
	return utc
}

func (s *Server) unfreezeLabClock() {
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	s.clockOverride = nil
}

func (s *Server) registerLabForensics() {
	s.mux.HandleFunc("POST "+labClockFreezePath, s.handleLabClockFreeze)
	s.mux.HandleFunc("POST "+labClockUnfreezePath, s.handleLabClockUnfreeze)
	s.mux.HandleFunc("POST "+labClockSetPath, s.handleLabClockSet)
	s.mux.HandleFunc("POST "+labBulkSeedPath, s.handleLabBulkSeed)
}

func (s *Server) requireLabForensicsRoot(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.LabForensics {
		azerrors.WriteARM(w, http.StatusForbidden, "AccessDenied",
			"Lab forensics is disabled. Set NOCTAXRIS_AZ_LAB_FORENSICS=1 to enable.")
		return false
	}
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if !p.IsRoot {
		azerrors.WriteARM(w, http.StatusForbidden, "AccessDenied", "Lab forensics requires Bearer root")
		return false
	}
	return true
}

func (s *Server) handleLabClockFreeze(w http.ResponseWriter, r *http.Request) {
	if !s.requireLabForensicsRoot(w, r) {
		return
	}
	t := s.freezeLabClock()
	writeJSON(w, http.StatusOK, map[string]any{
		"clockTime": t.Format(time.RFC3339),
		"frozen":    true,
	})
}

func (s *Server) handleLabClockUnfreeze(w http.ResponseWriter, r *http.Request) {
	if !s.requireLabForensicsRoot(w, r) {
		return
	}
	s.unfreezeLabClock()
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleLabClockSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireLabForensicsRoot(w, r) {
		return
	}
	var body struct {
		FixedTime string `json:"fixedTime"`
		ClockTime string `json:"clockTime"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	raw := strings.TrimSpace(body.FixedTime)
	if raw == "" {
		raw = strings.TrimSpace(body.ClockTime)
	}
	if raw == "" {
		azerrors.BadRequest(w, "fixedTime is required (RFC3339)")
		return
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			azerrors.BadRequest(w, "fixedTime must be RFC3339")
			return
		}
	}
	set := s.setLabClock(t)
	writeJSON(w, http.StatusOK, map[string]any{
		"clockTime": set.Format(time.RFC3339),
	})
}

func (s *Server) handleLabBulkSeed(w http.ResponseWriter, r *http.Request) {
	if !s.requireLabForensicsRoot(w, r) {
		return
	}
	var body struct {
		ScenarioID     string `json:"scenarioId"`
		SubscriptionID string `json:"subscriptionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	scenarioID := strings.ToLower(strings.TrimSpace(body.ScenarioID))
	if scenarioID == "" {
		azerrors.BadRequest(w, "scenarioId is required")
		return
	}
	sub := strings.TrimSpace(body.SubscriptionID)
	if sub == "" {
		sub = s.cfg.SubscriptionID
	}
	tenant := s.cfg.TenantID
	base := s.effectiveNow().UTC()
	activity, logs, assessments, err := labScenarioPack(sub, tenant, scenarioID, base)
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	for _, row := range activity {
		if err := s.store.AppendActivityLogRow(row); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	for _, row := range logs {
		if err := s.store.InsertLogAnalyticsRow(store.DefaultLogAnalyticsWorkspace, row.Table, row.Data); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	for _, a := range assessments {
		if err := s.store.UpsertARGResource(a.ID, "SecurityResources", a.Type, a.Name, a.Sub, a.RG, a.Tenant, a.Props); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scenarioId":       scenarioID,
		"activityLogCount": len(activity),
		"logRowCount":      len(logs),
		"assessmentCount":  len(assessments),
	})
}

type labLogRow struct {
	Table string
	Data  map[string]any
}

type labAssessment struct {
	ID, Type, Name, Sub, RG, Tenant, Props string
}

func labScenarioPack(sub, tenant, scenarioID string, base time.Time) ([]store.ActivityLogRow, []labLogRow, []labAssessment, error) {
	switch scenarioID {
	case "suspicious-signin":
		return labScenarioSuspiciousSignin(sub, tenant, base)
	case "blob-exfil":
		return labScenarioBlobExfil(sub, tenant, base)
	case "crypto-mining":
		return labScenarioCryptoMining(sub, tenant, base)
	default:
		return nil, nil, nil, fmt.Errorf("unknown scenarioId %q (known: suspicious-signin, blob-exfil, crypto-mining)", scenarioID)
	}
}

func labScenarioSuspiciousSignin(sub, tenant string, base time.Time) ([]store.ActivityLogRow, []labLogRow, []labAssessment, error) {
	t := base.Add(-2 * time.Hour)
	ident, _ := json.Marshal(map[string]any{
		"authorization": map[string]any{
			"evidence": map[string]any{"principalType": "ServicePrincipal", "principalId": "sp-contractor"},
		},
	})
	_ = tenant
	activity := []store.ActivityLogRow{{
		Timestamp:    t,
		Caller:       "sp-contractor",
		Operation:    "Microsoft.Authorization/login/action",
		ResourceID:   "/subscriptions/" + sub,
		Status:       "Succeeded",
		Message:      "service principal token",
		ClientIP:     "203.0.113.44",
		IdentityJSON: string(ident),
	}}
	logs := []labLogRow{{
		Table: store.LogTableAADServicePrincipalSignInLogs,
		Data: map[string]any{
			"TimeGenerated":        t.Format(time.RFC3339Nano),
			"AppId":                "sp-contractor",
			"ServicePrincipalName": "sp-contractor",
			"IPAddress":            "203.0.113.44",
			"ResultType":           "0",
			"ResourceDisplayName":  "https://management.azure.com",
		},
	}}
	return activity, logs, nil, nil
}

func labScenarioBlobExfil(sub, tenant string, base time.Time) ([]store.ActivityLogRow, []labLogRow, []labAssessment, error) {
	t1 := base.Add(-45 * time.Minute)
	t2 := base.Add(-30 * time.Minute)
	acct := "corp-sensitive"
	rid := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/" + acct
	ident, _ := json.Marshal(map[string]any{"claims": map[string]any{"appid": "investigator"}})
	activity := []store.ActivityLogRow{
		{
			Timestamp: t1, Caller: "investigator", Operation: "Microsoft.Storage/storageAccounts/listKeys/action",
			ResourceID: rid, Status: "Succeeded", ClientIP: "198.51.100.8", IdentityJSON: string(ident),
		},
		{
			Timestamp: t2, Caller: "investigator", Operation: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
			ResourceID: rid + "/blobServices/default/containers/finance/blobs/q1-report.csv",
			Status:     "Succeeded", ClientIP: "198.51.100.8", IdentityJSON: string(ident),
		},
	}
	logs := []labLogRow{{
		Table: store.LogTableDataPlaneRequests,
		Data: map[string]any{
			"TimeGenerated":   t2.Format(time.RFC3339Nano),
			"AccountName":     acct,
			"Uri":             "https://" + acct + ".blob.core.windows.net/finance/q1-report.csv",
			"OperationName":   "GetBlob",
			"CallerIpAddress": "198.51.100.8",
			"StatusCode":      200,
		},
	}}
	props, _ := json.Marshal(map[string]any{
		"displayName": "Storage data-plane read volume",
		"status":      map[string]any{"code": "Unhealthy"},
		"resourceDetails": map[string]any{
			"Source": "Azure",
			"Id":     rid,
		},
	})
	assessments := []labAssessment{{
		ID:     "/subscriptions/" + sub + "/providers/Microsoft.Security/assessments/blob-exfil-1",
		Type:   "microsoft.security/assessments",
		Name:   "blob-exfil-1",
		Sub:    sub,
		RG:     "rg1",
		Tenant: tenant,
		Props:  string(props),
	}}
	return activity, logs, assessments, nil
}

func labScenarioCryptoMining(sub, tenant string, base time.Time) ([]store.ActivityLogRow, []labLogRow, []labAssessment, error) {
	t := base.Add(-15 * time.Minute)
	vm := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/miner"
	activity := []store.ActivityLogRow{{
		Timestamp: t, Caller: "devops", Operation: "Microsoft.Compute/virtualMachines/write",
		ResourceID: vm, Status: "Succeeded", ClientIP: "203.0.113.90",
	}}
	logs := []labLogRow{{
		Table: store.LogTableContainerAppSystemLogs,
		Data: map[string]any{
			"TimeGenerated":    t.Format(time.RFC3339Nano),
			"ContainerAppName": "worker",
			"RevisionName":     "worker--0000001",
			"Log":              "CrashLoopBackOff",
			"Type":             "Normal",
			"Reason":           "Unhealthy",
		},
	}}
	props, _ := json.Marshal(map[string]any{
		"displayName":     "Virtual machine communicating with crypto-mining pool",
		"status":          map[string]any{"code": "Unhealthy", "cause": "CryptoMining"},
		"resourceDetails": map[string]any{"Source": "Azure", "Id": vm},
	})
	assessments := []labAssessment{{
		ID:     "/subscriptions/" + sub + "/providers/Microsoft.Security/assessments/crypto-mining-1",
		Type:   "microsoft.security/assessments",
		Name:   "crypto-mining-1",
		Sub:    sub,
		RG:     "rg1",
		Tenant: tenant,
		Props:  string(props),
	}}
	return activity, logs, assessments, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
