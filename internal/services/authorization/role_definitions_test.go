package authorization_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/authorization"
)

func TestRoleDefinitionsList(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID

	svc := &authorization.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: sub,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", nil)
	p := authn.Principal{ID: "root", IsRoot: true, Audiences: []string{authn.AudienceARM}}
	mux.ServeHTTP(rec, req.WithContext(authn.WithPrincipal(req.Context(), p)))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	vals, _ := body["value"].([]any)
	if len(vals) < 3 {
		t.Fatalf("want built-in roles, got %#v", body)
	}
}
