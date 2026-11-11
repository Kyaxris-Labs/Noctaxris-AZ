package keyvault_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestKeyVaultNameConflictAndAmbiguousLookup(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	first := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kvshared", strings.NewReader(`{"location":"eastus"}`))
	first.Header.Set("Authorization", "Bearer root-token")
	first.Header.Set("Content-Type", "application/json")
	firstRec := httptest.NewRecorder()
	mux.ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("put vault %d %s", firstRec.Code, firstRec.Body.String())
	}
	again := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kvshared", strings.NewReader(`{"location":"westus"}`))
	again.Header.Set("Authorization", "Bearer root-token")
	again.Header.Set("Content-Type", "application/json")
	againRec := httptest.NewRecorder()
	mux.ServeHTTP(againRec, again)
	if againRec.Code != http.StatusOK {
		t.Fatalf("update vault %d %s", againRec.Code, againRec.Body.String())
	}
	second := httptest.NewRequest(http.MethodPut, "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kvshared", strings.NewReader(`{"location":"eastus"}`))
	second.Header.Set("Authorization", "Bearer root-token")
	second.Header.Set("Content-Type", "application/json")
	secondRec := httptest.NewRecorder()
	mux.ServeHTTP(secondRec, second)
	if secondRec.Code != http.StatusConflict {
		t.Fatalf("duplicate vault %d %s", secondRec.Code, secondRec.Body.String())
	}

	if _, err := st.PutSecret("kvone", "s1", "vault-secret-value"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault("sub-a", "rg-a", "kvone", "eastus"); err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kvone"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-kv", Scope: scope, RoleDefinitionID: authz.RoleKeyVaultSecretsUser,
		PrincipalID: "sp-kv", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := es.MintAccessToken("sp-kv", authn.AudienceVault)
	if err != nil {
		t.Fatal(err)
	}
	okGet := httptest.NewRequest(http.MethodGet, "/keyvault/kvone/secrets/s1", nil)
	okGet.Header.Set("Authorization", "Bearer "+tok)
	okRec := httptest.NewRecorder()
	mux.ServeHTTP(okRec, okGet)
	if okRec.Code != http.StatusOK || !strings.Contains(okRec.Body.String(), "vault-secret-value") {
		t.Fatalf("secret get %d %s", okRec.Code, okRec.Body.String())
	}
	if err := st.UpsertKeyVault("sub-b", "rg-b", "kvone", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.LookupKeyVaultScope("kvone"); err != nil || ok {
		t.Fatalf("ambiguous vault ok=%v err=%v", ok, err)
	}
	denied := httptest.NewRequest(http.MethodGet, "/keyvault/kvone/secrets/s1", nil)
	denied.Header.Set("Authorization", "Bearer "+tok)
	deniedRec := httptest.NewRecorder()
	mux.ServeHTTP(deniedRec, denied)
	if deniedRec.Code != http.StatusNotFound || strings.Contains(deniedRec.Body.String(), "vault-secret-value") {
		t.Fatalf("ambiguous vault get %d %s", deniedRec.Code, deniedRec.Body.String())
	}
}
