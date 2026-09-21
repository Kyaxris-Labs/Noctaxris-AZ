package subscriptions_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
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

func TestGetSubscriptionAuthAndOK(t *testing.T) {
	st := openStore(t)
	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	path := "/subscriptions/" + config.DefaultSubscriptionID + "?api-version=2022-12-01"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d body=%s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sub map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &sub); err != nil {
		t.Fatal(err)
	}
	if sub["subscriptionId"] != config.DefaultSubscriptionID {
		t.Fatalf("subscription = %#v", sub)
	}
}

func TestResourceGroupPutGet(t *testing.T) {
	st := openStore(t)
	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	sub := config.DefaultSubscriptionID
	var rec *httptest.ResponseRecorder
	putPath := "/subscriptions/" + sub + "/resourcegroups/rg-lab?api-version=2022-12-01"
	for _, seg := range []string{"resourcegroups", "resourceGroups"} {
		p := "/subscriptions/" + sub + "/" + seg + "/rg-lab?api-version=2022-12-01"
		putReq := httptest.NewRequest(http.MethodPut, p, strings.NewReader(`{"location":"eastus"}`))
		putReq.Header.Set("Authorization", "Bearer "+rootToken)
		putReq.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, putReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("put %s status=%d body=%s", seg, rec.Code, rec.Body.String())
		}
	}
	var rg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rg); err != nil {
		t.Fatal(err)
	}
	if rg["name"] != "rg-lab" || rg["location"] != "eastus" {
		t.Fatalf("put rg = %#v", rg)
	}

	getReq := httptest.NewRequest(http.MethodGet, putPath, nil)
	getReq.Header.Set("Authorization", "Bearer "+rootToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, getReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestResourceGroupGetGroupMemberReader(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	if err := st.UpsertResourceGroup(sub, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}
	const (
		groupID  = "33333333-3333-3333-3333-333333333333"
		memberID = "11111111-1111-1111-1111-111111111111"
		otherID  = "22222222-2222-2222-2222-222222222222"
	)
	scope := "/subscriptions/" + sub + "/resourceGroups/rg-lab"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               scope + "/providers/Microsoft.Authorization/roleAssignments/ra-group",
		Scope:            scope,
		RoleDefinitionID: authz.RoleReader,
		PrincipalID:      groupID,
		PrincipalType:    "Group",
	}); err != nil {
		t.Fatal(err)
	}
	svc := &subscriptions.Service{
		Store: st,
		Authz: &authz.Evaluator{Assignments: st},
		PrincipalFrom: func(ctx context.Context) (authn.Principal, bool) {
			return authn.PrincipalFromContext(ctx)
		},
		SubscriptionID: sub,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	getPath := "/subscriptions/" + sub + "/resourceGroups/rg-lab?api-version=2022-12-01"
	serve := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, getPath, nil)
		req = req.WithContext(authn.WithPrincipal(req.Context(), authn.Principal{
			ID: id, Audiences: []string{authn.AudienceARM},
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := serve(memberID); rec.Code != http.StatusOK {
		t.Fatalf("member GET %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(otherID); rec.Code != http.StatusForbidden {
		t.Fatalf("non-member GET %d %s", rec.Code, rec.Body.String())
	}
}

func TestResourceGraphSubscriptionReader(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	tid := config.DefaultTenantID
	if err := st.UpsertARGResource("/subscriptions/"+sub+"/providers/Microsoft.Security/assessments/a1",
		"SecurityResources", "microsoft.security/assessments", "a1", sub, "rg1", tid, `{"status":"Unhealthy"}`); err != nil {
		t.Fatal(err)
	}
	readerID := "arg-reader"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleAssignments/arg-ra",
		Scope:            "/subscriptions/" + sub,
		RoleDefinitionID: authz.RoleReader,
		PrincipalID:      readerID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}
	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: sub,
		TenantID:       tid,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	argPath := "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
	body := `{"subscriptions":["` + sub + `"],"query":"SecurityResources"}`

	okReq := httptest.NewRequest(http.MethodPost, argPath, strings.NewReader(body))
	okReq = okReq.WithContext(authn.WithPrincipal(okReq.Context(), authn.Principal{
		ID: readerID, Audiences: []string{authn.AudienceARM},
	}))
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("reader ARG %d %s", okRec.Code, okRec.Body.String())
	}
	if !strings.Contains(okRec.Body.String(), "a1") {
		t.Fatalf("reader ARG missing row %s", okRec.Body.String())
	}

	denyReq := httptest.NewRequest(http.MethodPost, argPath, strings.NewReader(body))
	denyReq = denyReq.WithContext(authn.WithPrincipal(denyReq.Context(), authn.Principal{
		ID: "nobody", Audiences: []string{authn.AudienceARM},
	}))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRec := httptest.NewRecorder()
	mux.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("non-reader ARG %d %s", denyRec.Code, denyRec.Body.String())
	}
}
