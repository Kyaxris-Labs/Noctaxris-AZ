package azauth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
)

func TestRequireDataPlaneBearerNilAuthAndAudience(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, nil, nil, nil, "a", "/s"); ok {
		t.Fatal("nil auth must fail")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}

	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: tokLookup{id: "sp-ok"}}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-tok")
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, nil, nil, "a", "/s"); ok {
		t.Fatal("nil allows must fail audience")
	}
	if rec.Code != http.StatusUnauthorized && !strings.Contains(rec.Body.String(), "Audience") && rec.Code != http.StatusForbidden {
		// InvalidAuthenticationTokenAudience writes 401-shaped ARM error.
		if rec.Code < 400 {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	denyAud := func(authn.Principal) bool { return false }
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, nil, denyAud, "a", "/s"); ok {
		t.Fatal("audience deny must fail")
	}
}

func TestRequireDataPlaneBearerRBACBranches(t *testing.T) {
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: tokLookup{id: "sp-ok"}}
	allow := func(authn.Principal) bool { return true }
	scope := "/subscriptions/s/resourceGroups/rg"
	action := "Microsoft.AppConfiguration/configurationStores/keyValues/read"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-tok")

	// Non-root, empty action/scope -> forbidden.
	rec := httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, &authz.Evaluator{}, allow, "", scope); ok {
		t.Fatal("empty action must deny")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, &authz.Evaluator{}, allow, action, ""); ok {
		t.Fatal("empty scope must deny")
	}

	// Non-root, nil evaluator -> forbidden.
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, nil, allow, action, scope); ok {
		t.Fatal("nil evaluator must deny non-root")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}

	// Assigned reader allows.
	ev := &authz.Evaluator{Assignments: memAssignments{byScope: map[string][]authz.Assignment{
		scope: {{
			PrincipalID: "sp-ok", RoleDefinitionID: authz.RoleAppConfigDataReader, Scope: scope,
		}},
	}}}
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, ev, allow, action, scope); !ok {
		t.Fatalf("assigned reader denied: %s", rec.Body.String())
	}

	// Wrong principal denies.
	evDeny := &authz.Evaluator{Assignments: memAssignments{byScope: map[string][]authz.Assignment{
		scope: {{
			PrincipalID: "someone-else", RoleDefinitionID: authz.RoleAppConfigDataReader, Scope: scope,
		}},
	}}}
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, evDeny, allow, action, scope); ok {
		t.Fatal("unassigned principal must deny")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}

	// Evaluator error path.
	evErr := &authz.Evaluator{Assignments: errAssignments{err: errBoom{}}}
	rec = httptest.NewRecorder()
	if _, ok := azauth.RequireDataPlaneBearer(rec, req, auth, evErr, allow, action, scope); ok {
		t.Fatal("assignment error must fail")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireARMBearerRootAndNonRoot(t *testing.T) {
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok"}
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootReq.Header.Set("Authorization", "Bearer root-tok")
	rec := httptest.NewRecorder()
	if _, ok := azauth.RequireARMBearer(rec, rootReq, auth, nil, "Microsoft.Network/virtualNetworks/read", "/subscriptions/s"); !ok {
		t.Fatalf("root ARM denied: %s", rec.Body.String())
	}

	auth2 := &authn.Authenticator{
		RootClientID: "root", RootAccessToken: "root-tok",
		Tokens: tokLookup{id: "sp-arm"},
		Now:    func() time.Time { return time.Now().UTC() },
	}
	// Opaque store token without ARM audience claims -> audience fail unless AllowsARM true via empty aud path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-tok")
	rec = httptest.NewRecorder()
	_, _ = azauth.RequireARMBearer(rec, req, auth2, &authz.Evaluator{}, "Microsoft.Network/virtualNetworks/read", "/subscriptions/s")
	if rec.Code < 400 {
		t.Fatalf("non-root opaque without ARM aud should fail closed, status=%d body=%s", rec.Code, rec.Body.String())
	}
}

type errAssignments struct{ err error }

func (e errAssignments) ListRoleAssignmentsForScope(string) ([]authz.Assignment, error) {
	return nil, e.err
}

type errBoom struct{}

func (errBoom) Error() string { return "assignment boom" }
