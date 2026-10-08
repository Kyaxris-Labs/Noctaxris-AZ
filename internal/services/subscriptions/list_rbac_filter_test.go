package subscriptions_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func TestListSubscriptionsFiltersByRBAC(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	other := "11111111-1111-1111-1111-111111111111"
	if err := st.PutSubscription(other, "hidden", "Enabled", config.DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	reader := "sp-reader-1"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleAssignments/ra1",
		Scope:            "/subscriptions/" + sub,
		PrincipalID:      reader,
		RoleDefinitionID: authz.RoleReader,
		PrincipalType:    "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}

	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: sub,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/subscriptions?api-version=2022-12-01", nil)
	p := authn.Principal{ID: reader, Audiences: []string{authn.AudienceARM}}
	mux.ServeHTTP(rec, req.WithContext(authn.WithPrincipal(req.Context(), p)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	vals, _ := body["value"].([]any)
	if len(vals) != 1 {
		t.Fatalf("want 1 visible subscription, got %#v", body)
	}
	m, _ := vals[0].(map[string]any)
	if m["subscriptionId"] != sub {
		t.Fatalf("got %#v", m)
	}
}
