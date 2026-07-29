package functions_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/functions"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	testSub    = "00000000-0000-0000-0000-000000000002"
	testRG     = "rg1"
	testTenant = "00000000-0000-0000-0000-000000000001"
)

func mountFunctions(t *testing.T, principal func(*http.Request) (authn.Principal, bool)) *http.ServeMux {
	t.Helper()
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
	if err := st.EnsureRoot(testTenant, testSub, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertResourceGroup(testSub, testRG, "eastus"); err != nil {
		t.Fatal(err)
	}
	if principal == nil {
		principal = func(*http.Request) (authn.Principal, bool) {
			return authn.Principal{ID: "root", IsRoot: true}, true
		}
	}
	mux := http.NewServeMux()
	h := &functions.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	h.Mount(mux, principal)
	return mux
}

func TestFunctionAppCRUDAndInvoke(t *testing.T) {
	mux := mountFunctions(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites/fn1"

	body := `{"location":"eastus","kind":"functionapp","properties":{"labMockResponse":"{\"hello\":\"world\"}"}}`
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/functions/fn1/invoke", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["hello"] != "world" {
		t.Fatalf("invoke body=%#v", out)
	}

	req = httptest.NewRequest(http.MethodDelete, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFunctionAppAuthzDeny(t *testing.T) {
	mux := mountFunctions(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", IsRoot: false}, true
	})
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites/fn1"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}
