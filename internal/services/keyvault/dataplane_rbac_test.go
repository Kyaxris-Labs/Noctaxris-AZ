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

func TestKeyVaultDataPlaneRequiresVaultAudienceAndSecretsUser(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra1", Scope: scope, RoleDefinitionID: authz.RoleKeyVaultSecretsUser,
		PrincipalID: "sp-secrets", PrincipalType: "ServicePrincipal",
	}); err != nil {
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

	vaultTok, _, err := es.MintAccessToken("sp-secrets", authn.AudienceVault)
	if err != nil {
		t.Fatal(err)
	}
	get, _ := http.NewRequest(http.MethodGet, "/keyvault/kv1/secrets/missing?api-version=7.4", nil)
	get.Header.Set("Authorization", "Bearer "+vaultTok)
	grec := httptest.NewRecorder()
	mux.ServeHTTP(grec, get)
	if grec.Code != http.StatusNotFound {
		t.Fatalf("secrets user get missing secret status=%d body=%s", grec.Code, grec.Body.String())
	}

	put, _ := http.NewRequest(http.MethodPut, "/keyvault/kv1/secrets/s1?api-version=7.4",
		strings.NewReader(`{"value":"x"}`))
	put.Header.Set("Authorization", "Bearer "+vaultTok)
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusForbidden {
		t.Fatalf("secrets user put status=%d body=%s", prec.Code, prec.Body.String())
	}
}
