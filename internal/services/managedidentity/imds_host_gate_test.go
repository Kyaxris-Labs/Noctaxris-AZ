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

func TestIMDSHostGateAndEmptyRemoteAddr(t *testing.T) {
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
	if err := st.UpsertManagedIdentity("s", "rg", "mi1", "eastus", "pid-1", "cid-1"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &managedidentity.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
		Entra: es,
	}
	mux := http.NewServeMux()
	h.Register(mux)

	path := "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=cid-1"

	empty := httptest.NewRequest(http.MethodGet, path, nil)
	empty.Header.Set("Metadata", "true")
	empty.RemoteAddr = ""
	empty.Host = "169.254.169.254"
	erec := httptest.NewRecorder()
	mux.ServeHTTP(erec, empty)
	if erec.Code != http.StatusForbidden {
		t.Fatalf("empty RemoteAddr status=%d body=%s", erec.Code, erec.Body.String())
	}

	privateBadHost := httptest.NewRequest(http.MethodGet, path, nil)
	privateBadHost.Header.Set("Metadata", "true")
	privateBadHost.RemoteAddr = "10.0.0.5:9"
	privateBadHost.Host = "127.0.0.1:4599"
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, privateBadHost)
	if prec.Code != http.StatusForbidden {
		t.Fatalf("private peer without metadata Host status=%d body=%s", prec.Code, prec.Body.String())
	}

	privateMetaHost := httptest.NewRequest(http.MethodGet, path, nil)
	privateMetaHost.Header.Set("Metadata", "true")
	privateMetaHost.RemoteAddr = "10.0.0.5:9"
	privateMetaHost.Host = "169.254.169.254"
	okRec := httptest.NewRecorder()
	mux.ServeHTTP(okRec, privateMetaHost)
	if okRec.Code != http.StatusForbidden {
		t.Fatalf("RFC1918 peer must not mint even with metadata Host status=%d body=%s", okRec.Code, okRec.Body.String())
	}

	linkLocal := httptest.NewRequest(http.MethodGet, path, nil)
	linkLocal.Header.Set("Metadata", "true")
	linkLocal.RemoteAddr = "169.254.1.2:9"
	linkLocal.Host = "169.254.169.254"
	llRec := httptest.NewRecorder()
	mux.ServeHTTP(llRec, linkLocal)
	if llRec.Code != http.StatusOK {
		t.Fatalf("link-local peer status=%d body=%s", llRec.Code, llRec.Body.String())
	}

	loopback := httptest.NewRequest(http.MethodGet, path, nil)
	loopback.Header.Set("Metadata", "true")
	loopback.RemoteAddr = "127.0.0.1:9"
	loopback.Host = "127.0.0.1:4599"
	lrec := httptest.NewRecorder()
	mux.ServeHTTP(lrec, loopback)
	if lrec.Code != http.StatusOK {
		t.Fatalf("loopback peer status=%d body=%s", lrec.Code, lrec.Body.String())
	}
}
