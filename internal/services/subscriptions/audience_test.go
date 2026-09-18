package subscriptions_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func TestARMRejectsGraphAudience(t *testing.T) {
	st := openStore(t)
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	graphTok, _, err := es.MintAccessToken("sp-lab-1", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	armTok, _, err := es.MintAccessToken("root", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}

	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	auth := &authn.Authenticator{Tokens: st, JWT: es}

	call := func(tok string) *httptest.ResponseRecorder {
		t.Helper()
		p, err := auth.AuthenticateToken(tok)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/subscriptions?api-version=2022-12-01", nil)
		mux.ServeHTTP(rec, req.WithContext(authn.WithPrincipal(req.Context(), p)))
		return rec
	}

	denied := call(graphTok)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("Graph aud on ARM %d body=%s", denied.Code, denied.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(denied.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	errObj, _ := env["error"].(map[string]any)
	if errObj["code"] != "InvalidAuthenticationTokenAudience" {
		t.Fatalf("error %#v", env)
	}

	p, err := auth.AuthenticateToken(armTok)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowsARM() {
		t.Fatalf("ARM token must allow ARM: %+v", p)
	}
}
