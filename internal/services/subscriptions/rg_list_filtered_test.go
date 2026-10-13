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

// A caller without subscription-scope read sees only the resource groups it can
// read, matching Azure. A scoped Reader sees that one group; a principal with no
// grant gets an empty list rather than 403.
func TestListResourceGroupsFiltersByReadGrant(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	for _, name := range []string{"rg-visible", "rg-hidden"} {
		if err := st.UpsertResourceGroup(sub, name, "eastus"); err != nil {
			t.Fatal(err)
		}
	}
	const readerID = "sp-scoped-reader"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "ra-visible",
		Scope:            "/subscriptions/" + sub + "/resourceGroups/rg-visible",
		RoleDefinitionID: authz.RoleReader,
		PrincipalID:      readerID,
		PrincipalType:    "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}

	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: sub,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	listNames := func(id string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/subscriptions/"+sub+"/resourceGroups?api-version=2022-12-01", nil)
		req = req.WithContext(authn.WithPrincipal(req.Context(), authn.Principal{
			ID: id, Audiences: []string{authn.AudienceARM},
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
		}
		var body struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(body.Value))
		for _, rg := range body.Value {
			names = append(names, rg.Name)
		}
		return names
	}

	scoped := listNames(readerID)
	if len(scoped) != 1 || scoped[0] != "rg-visible" {
		t.Fatalf("scoped reader saw %v, want [rg-visible]", scoped)
	}

	none := listNames("sp-no-access")
	if len(none) != 0 {
		t.Fatalf("principal without a grant saw %v, want empty", none)
	}
}
