package aks_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/aks"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestAKSGetOmitsKubeConfigReaderDeniedCredential(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &aks.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	base := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1"
	put, _ := http.NewRequest(http.MethodPut, base, strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-tok")
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK {
		t.Fatalf("put %d %s", prec.Code, prec.Body.String())
	}
	if strings.Contains(prec.Body.String(), "kubeConfig") {
		t.Fatal("PUT response must omit kubeConfig")
	}

	get, _ := http.NewRequest(http.MethodGet, base, nil)
	get.Header.Set("Authorization", "Bearer root-tok")
	grec := httptest.NewRecorder()
	mux.ServeHTTP(grec, get)
	if grec.Code != http.StatusOK || strings.Contains(grec.Body.String(), "kubeConfig") {
		t.Fatalf("GET must omit kubeConfig: %d %s", grec.Code, grec.Body.String())
	}

	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-r", Scope: "/subscriptions/sub/resourceGroups/rg",
		RoleDefinitionID: authz.RoleReader, PrincipalID: "sp-r", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	readerTok, _, err := es.MintAccessToken("sp-r", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := http.NewRequest(http.MethodPost, base+"/listClusterAdminCredential", nil)
	cred.Header.Set("Authorization", "Bearer "+readerTok)
	crec := httptest.NewRecorder()
	mux.ServeHTTP(crec, cred)
	if crec.Code != http.StatusForbidden {
		t.Fatalf("reader credential %d %s", crec.Code, crec.Body.String())
	}

	rootCred, _ := http.NewRequest(http.MethodPost, base+"/listClusterAdminCredential", nil)
	rootCred.Header.Set("Authorization", "Bearer root-tok")
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, rootCred)
	if rrec.Code != http.StatusOK {
		t.Fatalf("root credential %d %s", rrec.Code, rrec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rrec.Body.Bytes(), &body)
	kcs, _ := body["kubeconfigs"].([]any)
	if len(kcs) == 0 {
		t.Fatalf("missing kubeconfigs %#v", body)
	}
}
