package functions_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/functions"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestFunctionAppARMRejectsGraphAudience(t *testing.T) {
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
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	graphTok, _, err := es.MintAccessToken("sp-lab-1", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	auth := &authn.Authenticator{Tokens: st, JWT: es}
	mux := http.NewServeMux()
	h := &functions.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	h.Mount(mux, func(r *http.Request) (authn.Principal, bool) {
		p, err := auth.AuthenticateRequest(r)
		if err != nil {
			return authn.Principal{}, false
		}
		return p, true
	})

	list := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites"
	denied := httptest.NewRequest(http.MethodGet, list, nil)
	denied.Header.Set("Authorization", "Bearer "+graphTok)
	drec := httptest.NewRecorder()
	mux.ServeHTTP(drec, denied)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("Graph aud on Function App ARM %d body=%s", drec.Code, drec.Body.String())
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
