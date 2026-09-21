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

func addClientSecret(t *testing.T, st *store.Store, tenant, clientID string) string {
	t.Helper()
	row, ok, err := st.GetEntraApp(tenant, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		if _, err := st.UpsertEntraApp(tenant, clientID, clientID); err != nil {
			t.Fatal(err)
		}
		row, ok, err = st.GetEntraApp(tenant, clientID)
		if err != nil || !ok {
			t.Fatalf("app after upsert: ok=%v err=%v", ok, err)
		}
	}
	obj := row.ObjectID
	if obj == "" {
		obj = row.AppID
	}
	secret := store.RandomToken(16)
	if _, err := st.AddPassword(obj, "application", "lab", authn.HashToken(secret), store.HintFromSecret(secret)); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestTokenMintClientCredentials(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	secret := addClientSecret(t, st, config.DefaultTenantID, "sp-lab-1")
	body := "grant_type=client_credentials&client_id=sp-lab-1&client_secret=" + secret
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
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected JWT, got %q", token)
	}
	expires, ok := resp["expires_in"].(float64)
	if !ok || int(expires) != 3600 {
		t.Fatalf("expires_in = %#v", resp["expires_in"])
	}

	id, found, err := st.LookupAccessToken(authn.HashToken(token), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !found || id != "sp-lab-1" {
		t.Fatalf("lookup principal=%q found=%v", id, found)
	}

	auth := &authn.Authenticator{Tokens: st, JWT: svc}
	p, err := auth.AuthenticateToken(token)
	if err != nil || p.ID != "sp-lab-1" {
		t.Fatalf("jwt auth: %#v %v", p, err)
	}
}

func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status=%d", rec.Code)
	}
	var disc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &disc)
	if disc["jwks_uri"] == nil || disc["token_endpoint"] == nil {
		t.Fatalf("discovery=%#v", disc)
	}

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/"+config.DefaultTenantID+"/discovery/v2.0/keys", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("jwks status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var jwks map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &jwks)
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("jwks=%#v", jwks)
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
