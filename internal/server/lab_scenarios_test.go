package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLabClockFreezeAndBulkSeedScenarios(t *testing.T) {
	srv, cfg := labForensicsServer(t, true, true, true, true)

	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:freeze", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("freeze status=%d body=%s", rec.Code, rec.Body.String())
	}
	var frozen map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen["frozen"] != true || frozen["clockTime"] == nil {
		t.Fatalf("freeze body %#v", frozen)
	}

	for _, scenario := range []string{"blob-exfil", "crypto-mining"} {
		body := `{"scenarioId":"` + scenario + `"}`
		req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/bulkSeed", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", scenario, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["scenarioId"] != scenario {
			t.Fatalf("%s resp %#v", scenario, out)
		}
		if out["activityLogCount"] == nil || out["logRowCount"] == nil {
			t.Fatalf("%s missing counts %#v", scenario, out)
		}
	}

	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/bulkSeed", bytes.NewReader([]byte(`{"scenarioId":"unknown-scenario"}`)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown scenario status=%d", rec.Code)
	}
}
