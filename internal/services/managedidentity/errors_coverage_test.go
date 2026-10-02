package managedidentity_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/managedidentity"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func miHarness(t *testing.T) (*http.ServeMux, *store.Store, *managedidentity.Handler) {
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
	_ = st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root")
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es}
	h := &managedidentity.Handler{
		Store: st, Auth: auth, Authz: &authz.Evaluator{Assignments: st}, Entra: es,
		TenantID: config.DefaultTenantID,
		AuditNow: func() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, st, h
}

func TestManagedIdentityAuthErrorsAndDeletes(t *testing.T) {
	mux, _, _ := miHarness(t)
	sub := config.DefaultSubscriptionID
	base := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-x"

	noAuth := httptest.NewRequest(http.MethodGet, base, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, noAuth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth %d %s", rec.Code, rec.Body.String())
	}

	badTok := httptest.NewRequest(http.MethodGet, base, nil)
	badTok.Header.Set("Authorization", "Bearer nope")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, badTok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token %d", rec.Code)
	}

	delMiss := httptest.NewRequest(http.MethodDelete, base, nil)
	delMiss.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, delMiss)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing %d %s", rec.Code, rec.Body.String())
	}

	sysMiss := httptest.NewRequest(http.MethodDelete,
		"/subscriptions/"+sub+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/systemAssignedIdentities/missing", nil)
	sysMiss.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, sysMiss)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sys delete missing %d", rec.Code)
	}

	nilAuth := &managedidentity.Handler{Store: nil, Auth: nil, Authz: &authz.Evaluator{}}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	rec = httptest.NewRecorder()
	nmux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil auth %d", rec.Code)
	}
}

func TestManagedIdentityIMDSValidationAndObjectID(t *testing.T) {
	mux, st, _ := miHarness(t)
	sub := config.DefaultSubscriptionID
	put := httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-obj",
		strings.NewReader(`{"location":"westus"}`))
	put.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	props, _ := body["properties"].(map[string]any)
	clientID, _ := props["clientId"].(string)
	principalID, _ := props["principalId"].(string)
	if clientID == "" || principalID == "" {
		t.Fatalf("props=%#v", props)
	}

	// Idempotent put keeps ids.
	put2 := httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-obj",
		strings.NewReader(`{"location":"eastus"}`))
	put2.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, put2)
	if rec.Code != http.StatusOK {
		t.Fatalf("put2 %d", rec.Code)
	}
	var body2 map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body2)
	props2, _ := body2["properties"].(map[string]any)
	if props2["clientId"] != clientID || props2["principalId"] != principalID {
		t.Fatalf("ids changed: %#v vs %#v", props, props2)
	}
	if body2["location"] != "westus" {
		t.Fatalf("expected preserved location, got %v", body2["location"])
	}

	cases := []struct {
		name string
		url  string
		meta string
		want int
	}{
		{"no-meta", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "", http.StatusBadRequest},
		{"no-api", "/metadata/identity/oauth2/token?resource=https://management.azure.com/&client_id=" + clientID, "true", http.StatusBadRequest},
		{"no-resource", "/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=" + clientID, "true", http.StatusBadRequest},
		{"by-object", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&object_id=" + principalID, "true", http.StatusOK},
		{"unknown-object", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&object_id=missing-oid", "true", http.StatusBadRequest},
		{"multi-no-id", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "true", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			if tc.meta != "" {
				req.Header.Set("Metadata", tc.meta)
			}
			req.RemoteAddr = "127.0.0.1:9"
			r := httptest.NewRecorder()
			mux.ServeHTTP(r, req)
			if r.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", r.Code, tc.want, r.Body.String())
			}
		})
	}

	// Single system-assigned allows default mint without client_id.
	sput := httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/systemAssignedIdentities/only",
		strings.NewReader(`{"location":"eastus"}`))
	sput.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, sput)
	if rec.Code != http.StatusOK {
		t.Fatalf("sys put %d %s", rec.Code, rec.Body.String())
	}
	_, _ = st.DeleteManagedIdentity(sub, "rg1", "id-obj")
	def := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	def.Header.Set("Metadata", "true")
	def.RemoteAddr = "169.254.169.254:9"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, def)
	if rec.Code != http.StatusOK {
		t.Fatalf("default system mint %d %s", rec.Code, rec.Body.String())
	}

	// System-assigned by client_id / object_id.
	var sysBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &sysBody)
	sysClient, _ := sysBody["client_id"].(string)
	loc, prin, cli, ok, err := st.GetSystemAssignedIdentity(sub, "rg1", "only")
	if err != nil || !ok {
		t.Fatalf("get sys %v %v", err, ok)
	}
	_ = loc
	byClient := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net&client_id="+cli, nil)
	byClient.Header.Set("Metadata", "true")
	byClient.RemoteAddr = "127.0.0.1:9"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, byClient)
	if rec.Code != http.StatusOK {
		t.Fatalf("sys client mint %d %s", rec.Code, rec.Body.String())
	}
	byOID := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net&object_id="+prin, nil)
	byOID.Header.Set("Metadata", "true")
	byOID.RemoteAddr = "127.0.0.1:9"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, byOID)
	if rec.Code != http.StatusOK {
		t.Fatalf("sys object mint %d %s", rec.Code, rec.Body.String())
	}
	_ = sysClient

	noEntra := &managedidentity.Handler{
		Store: st, Auth: &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		Authz: &authz.Evaluator{Assignments: st}, Entra: nil,
	}
	emux := http.NewServeMux()
	noEntra.Register(emux)
	req := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id="+cli, nil)
	req.Header.Set("Metadata", "true")
	req.RemoteAddr = "127.0.0.1:9"
	rec = httptest.NewRecorder()
	emux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no entra %d %s", rec.Code, rec.Body.String())
	}
}

func TestManagedIdentityAuthzDenyNonRoot(t *testing.T) {
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
	tok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	h := &managedidentity.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
		Entra: es,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+config.DefaultSubscriptionID+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", rec.Code, rec.Body.String())
	}
}
