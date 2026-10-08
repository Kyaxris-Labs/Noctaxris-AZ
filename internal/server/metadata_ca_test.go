package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestMetadataEndpointsAnonymousAndPublicURL(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secrets", "master.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	mk, err := store.LoadOrCreateMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), mk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		ListenAddr:      "0.0.0.0:4599",
		DataRoot:        filepath.Join(dir, "data"),
		MasterKeyPath:   keyPath,
		RootClientID:    "root",
		RootAccessToken: "tok",
		TenantID:        config.DefaultTenantID,
		SubscriptionID:  config.DefaultSubscriptionID,
		PublicURL:       "https://127.0.0.1:4599",
		TLSAuto:         true,
	}
	if cfg.IssuerBase() != "https://127.0.0.1:4599" {
		t.Fatalf("IssuerBase=%q", cfg.IssuerBase())
	}
	if !strings.HasPrefix(cfg.PublicBase(), "https://127.0.0.1") {
		t.Fatalf("PublicBase=%q", cfg.PublicBase())
	}

	srv := server.New(cfg, st, nil)
	h := srv.Handler()

	meta := httptest.NewRecorder()
	h.ServeHTTP(meta, httptest.NewRequest(http.MethodGet, "/metadata/endpoints", nil))
	if meta.Code != http.StatusOK {
		t.Fatalf("metadata %d %s", meta.Code, meta.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(meta.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	authnObj, _ := body["authentication"].(map[string]any)
	if authnObj["loginEndpoint"] != "https://127.0.0.1:4599/" {
		t.Fatalf("loginEndpoint %#v", authnObj)
	}
	if !authn.IsPublicPath("/metadata/endpoints") || !authn.IsPublicPath("/_noctaxris-az/ca.pem") {
		t.Fatal("expected public paths")
	}

	ca := httptest.NewRecorder()
	h.ServeHTTP(ca, httptest.NewRequest(http.MethodGet, "/_noctaxris-az/ca.pem", nil))
	if ca.Code != http.StatusOK {
		t.Fatalf("ca %d %s", ca.Code, ca.Body.String())
	}
	if !strings.Contains(ca.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("ca body %q", ca.Body.String())
	}
}
