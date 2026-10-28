package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestServerDiscoveryFollowsRequestHost(t *testing.T) {
	srv := newOriginServer(t, config.Config{
		ListenAddr: "0.0.0.0:4599",
		TenantID:   config.DefaultTenantID,
	})
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	origin := "http://203.0.113.10:59991"
	disc := fetchDiscovery(t, hs, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", "203.0.113.10:59991")
	if disc["issuer"] != origin+"/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("issuer=%v", disc["issuer"])
	}
	if disc["token_endpoint"] != origin+"/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("token_endpoint=%v", disc["token_endpoint"])
	}
	lab := fetchDiscovery(t, hs, "/_noctaxris-az/oidc-lab/.well-known/openid-configuration", "203.0.113.10:59991")
	if lab["issuer"] != origin+"/_noctaxris-az/oidc-lab" {
		t.Fatalf("lab issuer=%v", lab["issuer"])
	}
	if lab["token_endpoint"] != origin+"/_noctaxris-az/oidc-lab/token" {
		t.Fatalf("lab token_endpoint=%v", lab["token_endpoint"])
	}

	tlsSrv := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(tlsSrv.Close)
	tlsDisc := fetchDiscovery(t, tlsSrv, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", "203.0.113.10:59991")
	if tlsDisc["issuer"] != "https://203.0.113.10:59991/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("tls issuer=%v", tlsDisc["issuer"])
	}
	if tlsDisc["token_endpoint"] != "https://203.0.113.10:59991/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("tls token_endpoint=%v", tlsDisc["token_endpoint"])
	}
}

func TestServerDiscoveryKeepsPublicURL(t *testing.T) {
	srv := newOriginServer(t, config.Config{
		ListenAddr: "127.0.0.1:4599",
		TenantID:   config.DefaultTenantID,
		PublicURL:  "https://lab.example:8443",
	})
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	disc := fetchDiscovery(t, hs, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", "203.0.113.10:59991")
	if disc["issuer"] != "https://lab.example:8443/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("issuer=%v", disc["issuer"])
	}
	if disc["token_endpoint"] != "https://lab.example:8443/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("token_endpoint=%v", disc["token_endpoint"])
	}
}

func newOriginServer(t *testing.T, cfg config.Config) *server.Server {
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
	aud, err := audit.NewWriter(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	cfg.RootClientID = "root"
	cfg.RootAccessToken = "tok"
	return server.New(cfg, st, aud)
}

func fetchDiscovery(t *testing.T, hs *httptest.Server, path, host string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, hs.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s %d %s", path, res.StatusCode, body)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
