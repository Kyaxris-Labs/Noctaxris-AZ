package azauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
)

type tokLookup struct {
	id string
}

func (t tokLookup) LookupAccessToken(string, time.Time) (string, bool, error) {
	return t.id, t.id != "", nil
}

func TestRequireDataPlaneBearerAudienceAndRBAC(t *testing.T) {
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok"}
	ev := &authz.Evaluator{Assignments: memAssignments{byScope: map[string][]authz.Assignment{
		"/subscriptions/s/resourceGroups/rg": {{
			PrincipalID: "sp-ok", RoleDefinitionID: authz.RoleAppConfigDataReader,
			Scope: "/subscriptions/s/resourceGroups/rg",
		}},
	}}}

	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootReq.Header.Set("Authorization", "Bearer root-tok")
	rec := httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, rootReq, auth, ev, authn.Principal.AllowsAppConfig,
		"Microsoft.AppConfiguration/configurationStores/keyValues/read",
		"/subscriptions/s/resourceGroups/rg"); !ok {
		t.Fatalf("root denied: %s", rec.Body.String())
	}

	noAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, noAuth, auth, ev, authn.Principal.AllowsAppConfig, "a", "/s"); ok {
		t.Fatal("missing bearer must fail")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

type memAssignments struct {
	byScope map[string][]authz.Assignment
}

func (m memAssignments) ListRoleAssignmentsForScope(scope string) ([]authz.Assignment, error) {
	return m.byScope[scope], nil
}
