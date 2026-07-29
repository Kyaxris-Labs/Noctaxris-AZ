package monitor_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	testSub    = "00000000-0000-0000-0000-000000000002"
	testTenant = "00000000-0000-0000-0000-000000000001"
)

func mountMonitor(t *testing.T, principal func(*http.Request) (authn.Principal, bool)) (*http.ServeMux, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "secrets", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureRoot(testTenant, testSub, "root"); err != nil {
		t.Fatal(err)
	}
	if principal == nil {
		principal = func(*http.Request) (authn.Principal, bool) {
			return authn.Principal{ID: "root", IsRoot: true}, true
		}
	}
	mux := http.NewServeMux()
	h := &monitor.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	h.Mount(mux, principal)
	return mux, st
}

func TestMonitorActivityAndMetrics(t *testing.T) {
	mux, st := mountMonitor(t, nil)
	if err := st.AppendActivityLog("root", "Microsoft.Resources/subscriptions/read", "/subscriptions/"+testSub, "Succeeded", "lab"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/providers/Microsoft.Insights/eventtypes/management/values", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activity status=%d body=%s", rec.Code, rec.Body.String())
	}
	var act struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &act); err != nil {
		t.Fatal(err)
	}
	if len(act.Value) < 1 {
		t.Fatalf("expected activity rows, got %#v", act.Value)
	}

	metricBody := `{"name":"Requests","value":3,"resourceId":"/subscriptions/` + testSub + `"}`
	req = httptest.NewRequest(http.MethodPost,
		"/subscriptions/"+testSub+"/providers/Microsoft.Insights/metrics",
		bytes.NewReader([]byte(metricBody)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write metric status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/providers/Microsoft.Insights/metrics?metricnames=Requests", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list metrics status=%d body=%s", rec.Code, rec.Body.String())
	}
	var metrics struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if len(metrics.Value) < 1 {
		t.Fatalf("expected metrics, got %#v", metrics.Value)
	}
}

func TestMonitorAuthzDeny(t *testing.T) {
	mux, _ := mountMonitor(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", IsRoot: false}, true
	})
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/providers/Microsoft.Insights/eventtypes/management/values", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAppendActivityHelper(t *testing.T) {
	_, st := mountMonitor(t, nil)
	if err := monitor.AppendActivity(st, "root", "op", "/r", "Succeeded", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListActivityLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1 {
		t.Fatal("expected appended activity")
	}
}
