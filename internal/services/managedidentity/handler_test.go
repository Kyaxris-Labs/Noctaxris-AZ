package managedidentity_test

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
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/managedidentity"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestManagedIdentityIMDSToken(t *testing.T) {
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
		Store: st,
		Auth:  auth,
		Authz: &authz.Evaluator{Assignments: st},
		Entra: es,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	es.Mount(mux)

	sub := config.DefaultSubscriptionID
	put := httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1",
		strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body.String())
	}
	var idBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &idBody)
	props, _ := idBody["properties"].(map[string]any)
	clientID, _ := props["clientId"].(string)
	if clientID == "" {
		t.Fatalf("missing clientId: %#v", idBody)
	}

	imds := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id="+clientID, nil)
	imds.Header.Set("Metadata", "true")
	irec := httptest.NewRecorder()
	mux.ServeHTTP(irec, imds)
	if irec.Code != http.StatusOK {
		t.Fatalf("imds status=%d body=%s", irec.Code, irec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(irec.Body.Bytes(), &tok)
	access, _ := tok["access_token"].(string)
	if strings.Count(access, ".") != 2 {
		t.Fatalf("expected JWT: %#v", tok)
	}
	if _, ok := tok["expires_on"].(string); !ok {
		t.Fatalf("expires_on should be string: %#v", tok["expires_on"])
	}
	if _, ok := tok["not_before"].(string); !ok {
		t.Fatalf("not_before should be string: %#v", tok["not_before"])
	}
	p, err := auth.AuthenticateToken(access)
	if err != nil || p.ID == "" {
		t.Fatalf("bearer from imds: %#v %v", p, err)
	}

	bad := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	brec := httptest.NewRecorder()
	mux.ServeHTTP(brec, bad)
	if brec.Code != http.StatusBadRequest {
		t.Fatalf("missing Metadata header status=%d", brec.Code)
	}
}
