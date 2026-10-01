package managedidentity_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/managedidentity"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestIMDSRejectsUnknownClientID(t *testing.T) {
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
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &managedidentity.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
		Entra: es,
	}
	mux := http.NewServeMux()
	h.Register(mux)

	imds := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=not-a-real-mi", nil)
	imds.Header.Set("Metadata", "true")
	imds.RemoteAddr = "127.0.0.1:9"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, imds)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown client_id status=%d body=%s", rec.Code, rec.Body.String())
	}

	remote := httptest.NewRequest(http.MethodGet,
		"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=not-a-real-mi", nil)
	remote.Header.Set("Metadata", "true")
	remote.RemoteAddr = "203.0.113.10:9"
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, remote)
	if rrec.Code != http.StatusForbidden {
		t.Fatalf("public peer status=%d body=%s", rrec.Code, rrec.Body.String())
	}
}
