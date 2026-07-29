package appconfig_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appconfig"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	testSub = "00000000-0000-0000-0000-000000000002"
	testRG  = "rg1"
	testTenant = "00000000-0000-0000-0000-000000000001"
)

func mountAppConfig(t *testing.T, principal func(*http.Request) (authn.Principal, bool)) *http.ServeMux {
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
	h := &appconfig.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	h.Mount(mux, principal)
	return mux
}

func TestAppConfigStoreAndKV(t *testing.T) {
	mux := mountAppConfig(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg1"

	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put store status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get store status=%d body=%s", rec.Code, rec.Body.String())
	}

	kvBody := `{"value":"v1","label":""}`
	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg1/kv/my.key", bytes.NewReader([]byte(kvBody)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put kv status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg1/kv/my.key", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get kv status=%d body=%s", rec.Code, rec.Body.String())
	}
	var kv map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &kv); err != nil {
		t.Fatal(err)
	}
	if kv["value"] != "v1" || kv["key"] != "my.key" {
		t.Fatalf("kv=%#v", kv)
	}

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg1/kv", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list kv status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAppConfigAuthzDeny(t *testing.T) {
	mux := mountAppConfig(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", IsRoot: false}, true
	})
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg1"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}
