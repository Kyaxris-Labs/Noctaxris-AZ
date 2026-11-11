package appconfig_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appconfig"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestAppConfigNameConflictAndMissingStore(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "secrets", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	dirStore, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dirStore.Close() })
	if err := dirStore.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if err := dirStore.SetAppConfigKV("cfg-real", "secret", "", "appconfig-secret-value"); err != nil {
		t.Fatal(err)
	}
	if err := dirStore.UpsertAppConfig("sub-other", "rg-other", "cfg-real", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := dirStore.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-ac-default", Scope: "/subscriptions/" + config.DefaultSubscriptionID,
		RoleDefinitionID: authz.RoleAppConfigDataReader,
		PrincipalID:      "sp-ac-default", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: dirStore, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: dirStore, JWT: es}
	h := &appconfig.Handler{Store: dirStore, Authz: &authz.Evaluator{Assignments: dirStore}}
	mux := http.NewServeMux()
	h.Mount(mux, func(r *http.Request) (authn.Principal, bool) {
		p, err := auth.AuthenticateRequest(r)
		if err != nil {
			return authn.Principal{}, false
		}
		return p, true
	})

	put := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.AppConfiguration/configurationStores/cfg-new", strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-token")
	put.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	mux.ServeHTTP(putRec, put)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put store %d %s", putRec.Code, putRec.Body.String())
	}
	again := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.AppConfiguration/configurationStores/cfg-new", strings.NewReader(`{"location":"westus"}`))
	again.Header.Set("Authorization", "Bearer root-token")
	againRec := httptest.NewRecorder()
	mux.ServeHTTP(againRec, again)
	if againRec.Code != http.StatusOK {
		t.Fatalf("update store %d %s", againRec.Code, againRec.Body.String())
	}
	dup := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.AppConfiguration/configurationStores/cfg-new", strings.NewReader(`{"location":"eastus"}`))
	dup.Header.Set("Authorization", "Bearer root-token")
	dupRec := httptest.NewRecorder()
	mux.ServeHTTP(dupRec, dup)
	if dupRec.Code != http.StatusConflict || strings.Contains(dupRec.Body.String(), "appconfig-secret-value") {
		t.Fatalf("duplicate store %d %s", dupRec.Code, dupRec.Body.String())
	}

	readerTok, _, err := es.MintAccessToken("sp-ac-default", authn.AudienceAppConfig)
	if err != nil {
		t.Fatal(err)
	}
	noneTok, _, err := es.MintAccessToken("sp-ac-none", authn.AudienceAppConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{readerTok, noneTok} {
		req := httptest.NewRequest(http.MethodGet, "/appconfig/no-such-store/kv/secret", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "appconfig-secret-value") {
			t.Fatalf("missing store %d %s", rec.Code, rec.Body.String())
		}
	}

	if err := dirStore.UpsertAppConfig("sub-a", "rg-a", "cfg-real", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dirStore.GetAppConfigByName("cfg-real"); err != nil || ok {
		t.Fatalf("ambiguous store ok=%v err=%v", ok, err)
	}
	ambig := httptest.NewRequest(http.MethodGet, "/appconfig/cfg-real/kv/secret", nil)
	ambig.Header.Set("Authorization", "Bearer root-token")
	ambigRec := httptest.NewRecorder()
	mux.ServeHTTP(ambigRec, ambig)
	if ambigRec.Code != http.StatusNotFound || strings.Contains(ambigRec.Body.String(), "appconfig-secret-value") {
		t.Fatalf("ambiguous store get %d %s", ambigRec.Code, ambigRec.Body.String())
	}
}
