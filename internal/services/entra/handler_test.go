package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestTokenMintClientCredentials(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID}
	mux := http.NewServeMux()
	svc.Mount(mux)

	body := "grant_type=client_credentials&client_id=sp-lab-1&client_secret=unused"
	req := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	token, _ := resp["access_token"].(string)
	if token == "" || resp["token_type"] != "Bearer" {
		t.Fatalf("token resp = %#v", resp)
	}
	expires, ok := resp["expires_in"].(float64)
	if !ok || int(expires) != 3600 {
		t.Fatalf("expires_in = %#v", resp["expires_in"])
	}
	if _, ok := resp["ext_expires_in"]; !ok {
		t.Fatalf("missing ext_expires_in: %#v", resp)
	}

	id, found, err := st.LookupAccessToken(authn.HashToken(token), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !found || id != "sp-lab-1" {
		t.Fatalf("lookup principal=%q found=%v", id, found)
	}
}

func TestTokenRejectsBadGrant(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID}
	mux := http.NewServeMux()
	svc.Mount(mux)

	req := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=authorization_code&client_id=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
