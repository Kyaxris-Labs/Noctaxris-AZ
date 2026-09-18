package storage_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
)

func TestStorageAccountARMRejectsGraphAudience(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	graphTok, _, err := es.MintAccessToken("sp-lab-1", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	h := &storage.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	path := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1"

	denied, _ := http.NewRequest(http.MethodGet, path, nil)
	denied.Header.Set("Authorization", "Bearer "+graphTok)
	drec := httptest.NewRecorder()
	mux.ServeHTTP(drec, denied)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("Graph aud on Storage ARM %d body=%s", drec.Code, drec.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(drec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	errObj, _ := env["error"].(map[string]any)
	if errObj["code"] != "InvalidAuthenticationTokenAudience" {
		t.Fatalf("error %#v", env)
	}
}
