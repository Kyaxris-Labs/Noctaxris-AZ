package monitor_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestMonitorWrapUnauthAndAudience(t *testing.T) {
	mux, _ := mountMonitor(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{}, false
	})
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/providers/Microsoft.Insights/eventtypes/management/values", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d body=%s", rec.Code, rec.Body.String())
	}

	muxBadAud, _ := mountMonitor(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "u", Audiences: []string{authn.AudienceGraph}}, true
	})
	rec = httptest.NewRecorder()
	muxBadAud.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("bad audience status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteMetricValidationAndListTop(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
	base := "/subscriptions/" + testSub + "/providers/Microsoft.Insights/metrics"

	req := httptest.NewRequest(http.MethodPost, base, bytes.NewReader([]byte(`not-json`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, base, bytes.NewReader([]byte(`{"value":1}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, base, bytes.NewReader([]byte(`{"name":"Latency","value":9.5,"resourceId":"/subscriptions/`+testSub+`"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base+"?name=Latency&$top=1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Latency") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestActivityLogTopBoundariesAndIdentity(t *testing.T) {
	mux, st := mountMonitor(t, nil)
	if err := st.AppendActivityLogRow(store.ActivityLogRow{
		Timestamp:    time.Now().UTC(),
		Caller:       "root",
		Operation:    "Microsoft.Resources/subscriptions/read",
		ResourceID:   "/subscriptions/" + testSub,
		Status:       "Succeeded",
		ClientIP:     "127.0.0.1",
		IdentityJSON: `{"claims":{"oid":"x"}}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendActivityLogRow(store.ActivityLogRow{
		Timestamp:    time.Now().UTC(),
		Caller:       "root",
		Operation:    "Microsoft.Resources/subscriptions/read",
		ResourceID:   "/subscriptions/" + testSub,
		Status:       "Succeeded",
		ClientIP:     "127.0.0.1",
		IdentityJSON: "not-json-identity",
	}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"?$top=abc", "?$top=-1", "?$top=99999", "?top=2"} {
		req := httptest.NewRequest(http.MethodGet,
			"/subscriptions/"+testSub+"/providers/Microsoft.Insights/eventtypes/management/values"+q, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("top %s status=%d body=%s", q, rec.Code, rec.Body.String())
		}
	}
}

func TestSubscriptionDiagnosticSettingsCRUD(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
	path := "/subscriptions/" + testSub + "/providers/Microsoft.Insights/diagnosticSettings/sub-ds"
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(`{"properties":{"workspaceId":"/ws"}}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, path, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/subscriptions/"+testSub+"/providers/Microsoft.Insights/diagnosticSettings", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sub-ds") {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(`{bad`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json put %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, path+"-missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("delete missing %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodDelete, path, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete %d %s", rec.Code, rec.Body.String())
	}
}

func TestLogAnalyticsIngestSingleObjectAndPathWorkspace(t *testing.T) {
	_, st := mountMonitor(t, nil)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		LogsInject: true, SubscriptionID: testSub,
	}
	mux := http.NewServeMux()
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	req := httptest.NewRequest(http.MethodPost, "/loganalytics/default/ingest/CustomTable",
		bytes.NewReader([]byte(`{"Col":"one"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("single object ingest %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/default/ingest/CustomTable",
		bytes.NewReader([]byte(`not-json`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad ingest %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/loganalytics/ws-path/query",
		bytes.NewReader([]byte(`{"query":"CustomTable | take 1"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Fatalf("path workspace query %d %s", rec.Code, rec.Body.String())
	}
}

func TestAppendActivityNilStoreAndCustomNow(t *testing.T) {
	if err := monitor.AppendActivity(nil, "c", "op", "/r", "Succeeded", ""); err != nil {
		t.Fatalf("nil store: %v", err)
	}
	_, st := mountMonitor(t, nil)
	fixed := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		Now: func() time.Time { return fixed },
	}
	mux := http.NewServeMux()
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	path := "/subscriptions/" + testSub + "/providers/Microsoft.Insights/diagnosticSettings/clocked"
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(`{"properties":{}}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put with Now %d %s", rec.Code, rec.Body.String())
	}
}
