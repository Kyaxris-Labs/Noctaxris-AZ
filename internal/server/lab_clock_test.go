package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func labForensicsServer(t *testing.T, lab, activity, logs, defender bool) (*server.Server, config.Config) {
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
	cfg := config.Config{
		ListenAddr:      "127.0.0.1:0",
		AMQPListenAddr:  "127.0.0.1:0",
		DataRoot:        filepath.Join(dir, "data"),
		RootClientID:    "root",
		RootAccessToken: "test-root-token",
		TenantID:        config.DefaultTenantID,
		SubscriptionID:  config.DefaultSubscriptionID,
		LabForensics:    lab,
		ActivityInject:  activity,
		LogsInject:      logs,
		DefenderInject:  defender,
	}
	if err := st.EnsureRoot(cfg.TenantID, cfg.SubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	return server.New(cfg, st, nil), cfg
}

func TestLabClockDeniedWhenDisabled(t *testing.T) {
	srv, cfg := labForensicsServer(t, false, false, false, false)
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:freeze", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AccessDenied") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestInjectDeniedWhenDisabled(t *testing.T) {
	srv, cfg := labForensicsServer(t, true, false, false, false)
	for _, path := range []string{
		"/_noctaxris-az/lab/activityLog:inject",
		"/_noctaxris-az/lab/logs:inject",
		"/_noctaxris-az/lab/securityAssessments:inject",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"events":[]}`))
		req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestLabClockFreezeInjectAndBulkSeed(t *testing.T) {
	srv, cfg := labForensicsServer(t, true, true, true, true)
	fixed := "2020-01-02T03:04:05Z"
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:set", bytes.NewReader([]byte(`{"fixedTime":"`+fixed+`"}`)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set status=%d body=%s", rec.Code, rec.Body.String())
	}

	inject := `{"events":[{"caller":"alice","operationName":"Microsoft.Storage/storageAccounts/listKeys/action","resourceId":"/subscriptions/` + cfg.SubscriptionID + `/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct","callerIpAddress":"203.0.113.10","identity":{"token":"secret-value","appid":"alice"}}]}`
	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/activityLog:inject", bytes.NewReader([]byte(inject)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inject status=%d body=%s", rec.Code, rec.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+cfg.SubscriptionID+"/providers/Microsoft.Insights/eventtypes/management/values", nil)
	list.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, list)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "2020-01-02T03:04:05") {
		t.Fatalf("expected lab clock timestamp in %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Fatalf("identity token was not redacted: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "203.0.113.10") {
		t.Fatalf("missing caller IP: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/bulkSeed", bytes.NewReader([]byte(`{"scenarioId":"suspicious-signin"}`)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulkSeed status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:unfreeze", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unfreeze status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLabClockNonRootDenied(t *testing.T) {
	srv, cfg := labForensicsServer(t, true, false, false, false)
	st := srv // need a non-root token; mint via Entra
	_ = cfg
	req := httptest.NewRequest(http.MethodPost,
		"/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token parse %v %s", err, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:freeze", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec = httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-root freeze status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthExpiryIgnoresLabClock(t *testing.T) {
	srv, cfg := labForensicsServer(t, true, false, false, false)
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/clock:set",
		bytes.NewReader([]byte(`{"fixedTime":"1999-01-01T00:00:00Z"}`)))
	req.Header.Set("Authorization", "Bearer "+cfg.RootAccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set status=%d", rec.Code)
	}
	tokReq := httptest.NewRequest(http.MethodPost,
		"/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default"))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, tokReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	graph := httptest.NewRequest(http.MethodGet, "/v1.0/users", nil)
	graph.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, graph)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("token rejected as expired under frozen 1999 clock: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("graph users under frozen clock status=%d body=%s", rec.Code, rec.Body.String())
	}
}
