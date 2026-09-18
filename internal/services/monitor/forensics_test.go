package monitor_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
)

func TestDiagnosticSettingsCRUDAndActivity(t *testing.T) {
	mux, st := mountMonitor(t, nil)
	target := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1"
	path := target + "/providers/Microsoft.Insights/diagnosticSettings/to-la"
	body := `{"properties":{"workspaceId":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1","logs":[{"category":"StorageRead","enabled":true}],"metrics":[{"category":"AllMetrics","enabled":true}]}}`
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Microsoft.Insights/diagnosticSettings") {
		t.Fatalf("body=%s", rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, path, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, target+"/providers/Microsoft.Insights/diagnosticSettings", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "to-la") {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	rows, err := st.ListActivityLog(10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("activity after write: %v %v", rows, err)
	}
	req = httptest.NewRequest(http.MethodDelete, path, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, path, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete %d", rec.Code)
	}
}

func TestLogsInjectNamedTableAndKQL(t *testing.T) {
	_, st := mountMonitor(t, nil)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		LogsInject: true, ActivityInject: true, DefenderInject: true,
		SubscriptionID: testSub, TenantID: testTenant,
	}
	mux := http.NewServeMux()
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})

	body := `{"workspace":"ws1","table":"AzureActivity","rows":[{"TimeGenerated":"2020-01-02T03:04:05Z","OperationName":"Write","secret":"do-not-store"}]}`
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/logs:inject", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inject %d %s", rec.Code, rec.Body.String())
	}

	q := `{"query":"AzureActivity | where TimeGenerated >= datetime('2020-01-01T00:00:00Z') | project TimeGenerated, OperationName"}`
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/ws1/query", bytes.NewReader([]byte(q)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Write") {
		t.Fatalf("query body=%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "do-not-store") {
		t.Fatalf("secret leaked: %s", rec.Body.String())
	}

	bad := `{"table":"NotARealTable","rows":[{"x":1}]}`
	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/logs:inject", bytes.NewReader([]byte(bad)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown table %d %s", rec.Code, rec.Body.String())
	}
}

func TestDefenderAssessmentInjectARG(t *testing.T) {
	_, st := mountMonitor(t, nil)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		DefenderInject: true, SubscriptionID: testSub, TenantID: testTenant,
	}
	mux := http.NewServeMux()
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	body := `{"assessments":[{"name":"vm-crypto","properties":{"displayName":"crypto","status":{"code":"Unhealthy"},"resourceDetails":{"Source":"Azure","Id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/miner"}}}]}`
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/securityAssessments:inject", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inject %d %s", rec.Code, rec.Body.String())
	}
	rows, err := st.ListARGResources("SecurityResources", "microsoft.security/assessments")
	if err != nil || len(rows) == 0 {
		t.Fatalf("arg %v %v", rows, err)
	}
}

func TestActivityInjectFailClosed(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/activityLog:inject",
		bytes.NewReader([]byte(`{"events":[{"operationName":"x"}]}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLogAnalyticsTimeGeneratedAndProject(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/loganalytics/ws1/ingest/T",
		bytes.NewReader([]byte(`[{"TimeGenerated":"2020-06-01T00:00:00Z","Col":"keep","Other":"drop"},{"TimeGenerated":"2019-01-01T00:00:00Z","Col":"old"}]`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/ws1/query",
		bytes.NewReader([]byte(`{"query":"T | where TimeGenerated >= datetime('2020-01-01T00:00:00Z') | project Col"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Tables []struct {
			Rows []map[string]any `json:"rows"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tables) == 0 || len(out.Tables[0].Rows) != 1 {
		t.Fatalf("rows %#v", out)
	}
	if _, ok := out.Tables[0].Rows[0]["Other"]; ok {
		t.Fatal("project leaked Other")
	}
	if out.Tables[0].Rows[0]["Col"] != "keep" {
		t.Fatalf("%#v", out.Tables[0].Rows[0])
	}
}
