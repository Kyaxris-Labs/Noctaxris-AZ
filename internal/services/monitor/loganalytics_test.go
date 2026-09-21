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

func TestLogAnalyticsQueryWorkspaceReader(t *testing.T) {
	_, st := mountMonitor(t, nil)
	wsARM := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws-lab"
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		SubscriptionID: testSub,
	}
	rootMux := http.NewServeMux()
	h.Mount(rootMux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	req := httptest.NewRequest(http.MethodPut, wsARM, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	rootMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ws %d %s", rec.Code, rec.Body.String())
	}
	if err := st.IngestLogAnalyticsRow("ws-lab", "AzureActivity", `{"OperationName":"InjectedWrite"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.IngestLogAnalyticsRow("default", "AzureActivity", `{"OperationName":"DefaultOnly"}`); err != nil {
		t.Fatal(err)
	}
	readerID := "logs-reader"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Authorization/roleAssignments/ws-ra",
		Scope:            "/subscriptions/" + testSub + "/resourceGroups/rg1",
		RoleDefinitionID: authz.RoleReader,
		PrincipalID:      readerID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}

	readerMux := http.NewServeMux()
	h.Mount(readerMux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: readerID, Audiences: []string{authn.AudienceARM}}, true
	})
	q := httptest.NewRequest(http.MethodPost, "/loganalytics/ws-lab/query",
		bytes.NewReader([]byte(`{"query":"AzureActivity | take 5"}`)))
	qrec := httptest.NewRecorder()
	readerMux.ServeHTTP(qrec, q)
	if qrec.Code != http.StatusOK {
		t.Fatalf("reader query %d %s", qrec.Code, qrec.Body.String())
	}
	if !strings.Contains(qrec.Body.String(), "InjectedWrite") {
		t.Fatalf("workspace rows missing: %s", qrec.Body.String())
	}
	if strings.Contains(qrec.Body.String(), "DefaultOnly") {
		t.Fatalf("default workspace leaked: %s", qrec.Body.String())
	}

	denyMux := http.NewServeMux()
	h.Mount(denyMux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", Audiences: []string{authn.AudienceARM}}, true
	})
	dq := httptest.NewRequest(http.MethodPost, "/loganalytics/ws-lab/query",
		bytes.NewReader([]byte(`{"query":"AzureActivity | take 5"}`)))
	drec := httptest.NewRecorder()
	denyMux.ServeHTTP(drec, dq)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("non-member query %d %s", drec.Code, drec.Body.String())
	}

	logsID := "la-reader"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Authorization/roleAssignments/la-ra",
		Scope:            "/subscriptions/" + testSub + "/resourceGroups/rg1",
		RoleDefinitionID: authz.RoleLogAnalyticsReader,
		PrincipalID:      logsID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}
	logsMux := http.NewServeMux()
	h.Mount(logsMux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: logsID, Audiences: []string{authn.AudienceARM}}, true
	})
	lq := httptest.NewRequest(http.MethodPost, "/loganalytics/ws-lab/query",
		bytes.NewReader([]byte(`{"query":"AzureActivity | take 5"}`)))
	lrec := httptest.NewRecorder()
	logsMux.ServeHTTP(lrec, lq)
	if lrec.Code != http.StatusOK || !strings.Contains(lrec.Body.String(), "InjectedWrite") {
		t.Fatalf("logs reader query %d %s", lrec.Code, lrec.Body.String())
	}
}
