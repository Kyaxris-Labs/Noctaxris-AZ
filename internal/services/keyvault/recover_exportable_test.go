package keyvault_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestRecoverSecretHonorsNonExportableCertificate(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}
	h := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer root-token") }

	put, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/certificates/locked",
		strings.NewReader(`{"value":"-----BEGIN CERTIFICATE-----\nLAB\n-----END CERTIFICATE-----","policy":{"key_props":{"exportable":true}}}`))
	auth(put)
	put.Header.Set("Content-Type", "application/json")
	pres, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	if pres.StatusCode != http.StatusOK {
		t.Fatalf("put exportable cert %d", pres.StatusCode)
	}

	// Later non-exportable policy version blocks secret disclosure.
	locked, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/certificates/locked",
		strings.NewReader(`{"value":"-----BEGIN CERTIFICATE-----\nLAB2\n-----END CERTIFICATE-----","policy":{"key_props":{"exportable":false}}}`))
	auth(locked)
	locked.Header.Set("Content-Type", "application/json")
	lres, err := http.DefaultClient.Do(locked)
	if err != nil {
		t.Fatal(err)
	}
	lres.Body.Close()
	if lres.StatusCode != http.StatusOK {
		t.Fatalf("put non-exportable cert %d", lres.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/secrets/locked", nil)
	auth(get)
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(gres.Body)
	gres.Body.Close()
	if gres.StatusCode != http.StatusForbidden {
		t.Fatalf("GET non-exportable secret %d", gres.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/keyvault/kv1/secrets/locked", nil)
	auth(del)
	dres, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	dres.Body.Close()
	if dres.StatusCode != http.StatusOK {
		t.Fatalf("soft-delete %d", dres.StatusCode)
	}

	rec, _ := http.NewRequest(http.MethodPost, srv.URL+"/keyvault/kv1/deletedsecrets/locked/recover", nil)
	auth(rec)
	rres, err := http.DefaultClient.Do(rec)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rres.Body)
	rres.Body.Close()
	if rres.StatusCode != http.StatusForbidden {
		t.Fatalf("recover non-exportable expected 403, got %d %s", rres.StatusCode, body)
	}
}
