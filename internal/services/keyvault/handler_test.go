package keyvault_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestKeyVaultUnauthenticatedAndSecretRoundtrip(t *testing.T) {
	st := openStore(t)
	defer st.Close()
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

	unauth, err := http.Get(srv.URL + "/keyvault/kv1/secrets/s1?api-version=7.4")
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", unauth.StatusCode)
	}
	wa := unauth.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") || !strings.Contains(wa, "authorization=") {
		t.Fatalf("WWW-Authenticate: %q", wa)
	}

	putReq, err := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/secrets/s1?api-version=7.4",
		strings.NewReader(`{"value":"super-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	putReq.Header.Set("Authorization", "Bearer root-token")
	putReq.Header.Set("Content-Type", "application/json")
	putRes, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	defer putRes.Body.Close()
	if putRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putRes.Body)
		t.Fatalf("put status %d: %s", putRes.StatusCode, body)
	}

	getReq, err := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/secrets/s1?api-version=7.4", nil)
	if err != nil {
		t.Fatal(err)
	}
	getReq.Header.Set("Authorization", "Bearer root-token")
	getRes, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getRes.Body.Close()
	if getRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getRes.Body)
		t.Fatalf("get status %d: %s", getRes.StatusCode, body)
	}
	var got struct {
		Value string `json:"value"`
		ID    string `json:"id"`
	}
	if err := json.NewDecoder(getRes.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Value != "super-secret" {
		t.Fatalf("value %q", got.Value)
	}
	if !strings.Contains(got.ID, "/keyvault/kv1/secrets/s1/") {
		t.Fatalf("id %q", got.ID)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 3)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
