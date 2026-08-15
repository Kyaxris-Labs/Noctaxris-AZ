package monitor_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogAnalyticsWorkspaceIngestQuery(t *testing.T) {
	mux, _ := mountMonitor(t, nil)
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
	req = httptest.NewRequest(http.MethodPost, "/loganalytics/ws1/ingest/T",
		bytes.NewReader([]byte(`[{"Col":"x"},{"Col":"y"}]`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest %d %s", rec.Code, rec.Body.String())
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
	// wrong path may 404 from mux; also test missing workspace name
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing ws %d", rec.Code)
	}
}
