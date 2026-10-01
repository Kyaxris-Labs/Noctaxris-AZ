package appconfig_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appconfig"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestAppConfigDataPlaneAudienceAndReaderDeny(t *testing.T) {
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
	if err := st.EnsureRoot(config.DefaultTenantID, testSub, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertResourceGroup(testSub, testRG, "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfig(testSub, testRG, "cfg1", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("cfg1", "secret", "", "v"); err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/" + testSub + "/resourceGroups/" + testRG
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-reader", Scope: scope, RoleDefinitionID: authz.RoleReader,
		PrincipalID: "sp-reader", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-data", Scope: scope, RoleDefinitionID: authz.RoleAppConfigDataReader,
		PrincipalID: "sp-data", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	auth := &authn.Authenticator{Tokens: st, JWT: es}
	h := &appconfig.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	mux := http.NewServeMux()
	h.Mount(mux, func(r *http.Request) (authn.Principal, bool) {
		p, err := auth.AuthenticateRequest(r)
		if err != nil {
			return authn.Principal{}, false
		}
		return p, true
	})

	readerTok, _, err := es.MintAccessToken("sp-reader", authn.AudienceAppConfig)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/appconfig/cfg1/kv/secret", nil)
	req.Header.Set("Authorization", "Bearer "+readerTok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("classic Reader kv get %d %s", rec.Code, rec.Body.String())
	}

	graphTok, _, err := es.MintAccessToken("sp-data", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg1/kv/secret", nil)
	req.Header.Set("Authorization", "Bearer "+graphTok)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Graph data reader %d %s", rec.Code, rec.Body.String())
	}

	cfgTok, _, err := es.MintAccessToken("sp-data", authn.AudienceAppConfig)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg1/kv/secret", nil)
	req.Header.Set("Authorization", "Bearer "+cfgTok)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("App Config Data Reader %d %s", rec.Code, rec.Body.String())
	}
}

func TestAppConfigDeleteCascadesSnapshots(t *testing.T) {
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
	if err := st.EnsureRoot(config.DefaultTenantID, testSub, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfig(testSub, testRG, "cfg-leak", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("cfg-leak", "k", "", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfigSnapshot("cfg-leak", "freeze1", "ready"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAppConfig(testSub, testRG, "cfg-leak"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfig(testSub, testRG, "cfg-leak", "eastus"); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := st.GetAppConfigSnapshot("cfg-leak", "freeze1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("snapshot must not survive store delete")
	}
}
