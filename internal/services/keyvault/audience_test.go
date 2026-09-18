package keyvault_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestKeyVaultARMRejectsGraphAudience(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	graphTok, _, err := es.MintAccessToken("sp-lab-1", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	h := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	arm := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
	denied, _ := http.NewRequest(http.MethodGet, arm, nil)
	denied.Header.Set("Authorization", "Bearer "+graphTok)
	drec := httptest.NewRecorder()
	mux.ServeHTTP(drec, denied)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("Graph aud on Key Vault ARM %d body=%s", drec.Code, drec.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(drec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	errObj, _ := env["error"].(map[string]any)
	if errObj["code"] != "InvalidAuthenticationTokenAudience" {
		t.Fatalf("error %#v", env)
	}

	put, _ := http.NewRequest(http.MethodPut, "/keyvault/kv1/secrets/s1?api-version=7.4",
		strings.NewReader(`{"value":"from-graph-aud"}`))
	put.Header.Set("Authorization", "Bearer "+graphTok)
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK {
		b, _ := io.ReadAll(prec.Body)
		t.Fatalf("data plane Graph aud %d: %s", prec.Code, b)
	}
}
