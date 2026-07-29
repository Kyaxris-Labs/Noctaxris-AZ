package subscriptions_test

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
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	sub := config.DefaultSubscriptionID
	putPath := "/subscriptions/" + sub + "/resourcegroups/rg-lab?api-version=2022-12-01"
	putReq := httptest.NewRequest(http.MethodPut, putPath, strings.NewReader(`{"location":"eastus"}`))
	putReq.Header.Set("Authorization", "Bearer "+rootToken)
	putReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, putReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body.String())
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
