package monitor_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
)

func TestLogAnalyticsWorkspaceIngestQuery(t *testing.T) {
	mux, st := mountMonitor(t, nil)
	ws := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1"
	req := httptest.NewRequest(http.MethodPut, ws, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ws %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, ws, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get ws %d %s", rec.Code, rec.Body.String())
	}
	if err := st.IngestLogAnalyticsRow("ws1", "T", `{"Col":"x"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.IngestLogAnalyticsRow("ws1", "T", `{"Col":"y"}`); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/ws1/query",
		bytes.NewReader([]byte(`{"query":"T | take 1"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, ws+"missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing ws %d", rec.Code)
	}
}

func TestLogAnalyticsHTTPIngestRequiresLogsInject(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/loganalytics/default/ingest/AzureActivity",
		bytes.NewReader([]byte(`[{"OperationName":"Write"}]`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with inject off, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "NOCTAXRIS_AZ_LOGS_INJECT") {
		t.Fatalf("body=%s", rec.Body.String())
	}

	_, st := mountMonitor(t, nil)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		LogsInject: true,
	}
	on := http.NewServeMux()
	h.Mount(on, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/default/ingest/AzureActivity",
		bytes.NewReader([]byte(`[{"OperationName":"Write"}]`)))
	rec = httptest.NewRecorder()
	on.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root ingest with flag %d %s", rec.Code, rec.Body.String())
	}

	denied := http.NewServeMux()
	h.Mount(denied, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", IsRoot: false, Audiences: []string{authn.AudienceARM}}, true
	})
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/default/ingest/AzureActivity",
		bytes.NewReader([]byte(`[{"OperationName":"Write"}]`)))
	rec = httptest.NewRecorder()
	denied.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-root ingest %d %s", rec.Code, rec.Body.String())
	}
}
