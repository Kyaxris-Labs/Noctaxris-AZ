package azauth_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/network"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestRequireAuthzEvaluatorNilWritesForbidden(t *testing.T) {
	rec := httptest.NewRecorder()
	if azauth.RequireAuthzEvaluator(rec, false, nil) {
		t.Fatal("non-root with nil Authz must be denied")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	if !azauth.RequireAuthzEvaluator(rec, true, nil) {
		t.Fatal("root with nil Authz must be allowed")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("root must not write error status, got %d", rec.Code)
	}

	ev := &authz.Evaluator{}
	rec = httptest.NewRecorder()
	if !azauth.RequireAuthzEvaluator(rec, false, ev) {
		t.Fatal("non-nil Authz must continue")
	}
}

func TestNetworkRequireNilAuthzWritesForbidden(t *testing.T) {
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
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	auth := &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: st, JWT: es}
	h := &network.Handler{Store: st, Auth: auth, Authz: nil}
	mux := http.NewServeMux()
	h.Register(mux)

	tok, _, err := es.MintAccessToken("sp-nil-authz", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("nil Authz non-root status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AuthorizationFailed") {
		t.Fatalf("expected AuthorizationFailed, got %s", rec.Body.String())
	}

	rootReq := httptest.NewRequest(http.MethodGet,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1", nil)
	rootReq.Header.Set("Authorization", "Bearer root-tok")
	rootRec := httptest.NewRecorder()
	mux.ServeHTTP(rootRec, rootReq)
	if rootRec.Code == http.StatusForbidden {
		t.Fatalf("root with nil Authz must not be forbidden: %s", rootRec.Body.String())
	}
}
