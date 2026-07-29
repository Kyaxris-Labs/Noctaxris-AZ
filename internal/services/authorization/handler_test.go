package authorization_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/authorization"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const rootToken = "noctaxris-az-test-root-token"

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	return st
}

func withAuth(st *store.Store, next http.Handler) http.Handler {
	a := &authn.Authenticator{
		RootClientID:    "root",
		RootAccessToken: rootToken,
		Tokens:          st,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, err := a.AuthenticateRequest(r); err == nil {
			r = r.WithContext(authn.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

func TestRoleAssignmentPut(t *testing.T) {
	st := openStore(t)
	svc := &authorization.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	sub := config.DefaultSubscriptionID
	name := "ra-lab-1"
	path := "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleAssignments/" + name + "?api-version=2022-04-01"
	body := `{
		"properties": {
			"roleDefinitionId": "` + authz.RoleReader + `",
			"principalId": "sp-lab-1",
			"principalType": "ServicePrincipal"
		}
	}`
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body.String())
	}
	var ra map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ra); err != nil {
		t.Fatal(err)
	}
	if ra["name"] != name {
		t.Fatalf("name = %#v", ra["name"])
	}
	props, _ := ra["properties"].(map[string]any)
	if props["principalId"] != "sp-lab-1" {
		t.Fatalf("properties = %#v", props)
	}

	id := "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleAssignments/" + name
	got, ok, err := st.GetRoleAssignment(id)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.PrincipalID != "sp-lab-1" {
		t.Fatalf("stored = %#v ok=%v", got, ok)
	}

	getReq := httptest.NewRequest(http.MethodGet, path, nil)
	getReq.Header.Set("Authorization", "Bearer "+rootToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, getReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRoleAssignmentPutAtResourceGroup(t *testing.T) {
	st := openStore(t)
	if err := st.UpsertResourceGroup(config.DefaultSubscriptionID, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}
	svc := &authorization.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	sub := config.DefaultSubscriptionID
	name := "ra-rg-1"
	path := "/subscriptions/" + sub + "/resourceGroups/rg-lab/providers/Microsoft.Authorization/roleAssignments/" + name + "?api-version=2022-04-01"
	body := `{"properties":{"roleDefinitionId":"` + authz.RoleContributor + `","principalId":"sp-2","principalType":"User"}}`
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body.String())
	}
	var ra map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ra); err != nil {
		t.Fatal(err)
	}
	props, _ := ra["properties"].(map[string]any)
	if props["principalType"] != "User" || props["scope"] != "/subscriptions/"+sub+"/resourceGroups/rg-lab" {
		t.Fatalf("properties = %#v", props)
	}
}
