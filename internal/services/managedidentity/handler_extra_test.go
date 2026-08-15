package managedidentity_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/managedidentity"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestManagedIdentityCRUDAndSystemAssigned(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root")
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es}
	h := &managedidentity.Handler{
		Store: st, Auth: auth, Authz: &authz.Evaluator{Assignments: st}, Entra: es, TenantID: config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	sub := config.DefaultSubscriptionID
	base := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities"
	put := httptest.NewRequest(http.MethodPut, base+"/id2", strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	get := httptest.NewRequest(http.MethodGet, base+"/id2", nil)
	get.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d", rec.Code)
	}
	list := httptest.NewRequest(http.MethodGet, base, nil)
	list.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, list)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d", rec.Code)
	}
	sysBase := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/systemAssignedIdentities"
	sput := httptest.NewRequest(http.MethodPut, sysBase+"/sys1", strings.NewReader(`{"location":"eastus"}`))
	sput.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, sput)
	if rec.Code != http.StatusOK {
		t.Fatalf("put sys %d %s", rec.Code, rec.Body.String())
	}
	sget := httptest.NewRequest(http.MethodGet, sysBase+"/sys1", nil)
	sget.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, sget)
	if rec.Code != http.StatusOK {
		t.Fatalf("get sys %d %s", rec.Code, rec.Body.String())
	}
	sdel := httptest.NewRequest(http.MethodDelete, sysBase+"/sys1", nil)
	sdel.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, sdel)
	if rec.Code != http.StatusOK {
		t.Fatalf("del sys %d", rec.Code)
	}
	del := httptest.NewRequest(http.MethodDelete, base+"/id2", nil)
	del.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("del %d", rec.Code)
	}
	miss := httptest.NewRequest(http.MethodGet, base+"/missing", nil)
	miss.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, miss)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing %d", rec.Code)
	}
}
