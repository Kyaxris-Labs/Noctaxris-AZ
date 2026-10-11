package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestHostRewriteStillRequiresAuth(t *testing.T) {
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
	if _, err := st.UpsertStorageAccount(config.DefaultSubscriptionID, "rg", "acct1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("acct1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob("acct1", "c1", "secret.bin", []byte("x"), "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault(config.DefaultSubscriptionID, "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		ListenAddr:      "127.0.0.1:4599",
		DataRoot:        filepath.Join(dir, "data"),
		MasterKeyPath:   keyPath,
		RootClientID:    "root",
		RootAccessToken: "root-tok",
		TenantID:        config.DefaultTenantID,
		SubscriptionID:  config.DefaultSubscriptionID,
		PublicURL:       "https://127.0.0.1:4599",
	}
	h := server.New(cfg, st, nil).Handler()

	// Host-style blob list without SharedKey/SAS/Bearer must not dump blobs.
	blobRec := httptest.NewRecorder()
	blobReq := httptest.NewRequest(http.MethodGet, "/c1?restype=container&comp=list", nil)
	blobReq.Host = "acct1.blob.core.windows.net"
	h.ServeHTTP(blobRec, blobReq)
	if blobRec.Code == http.StatusOK {
		t.Fatalf("unauthenticated host-style blob list must fail, got %d body=%s", blobRec.Code, blobRec.Body.String())
	}

	// Host-style vault secret without Bearer must fail closed.
	kvRec := httptest.NewRecorder()
	kvReq := httptest.NewRequest(http.MethodGet, "/secrets/s1?api-version=7.4", nil)
	kvReq.Host = "kv1.vault.azure.net"
	h.ServeHTTP(kvRec, kvReq)
	if kvRec.Code == http.StatusOK {
		t.Fatalf("unauthenticated host-style vault get must fail, got %d", kvRec.Code)
	}

	// Path-style JSON list without credentials still fails (challenge path stays fail-closed).
	pathRec := httptest.NewRecorder()
	h.ServeHTTP(pathRec, httptest.NewRequest(http.MethodGet, "/blob/acct1/c1", nil))
	if pathRec.Code == http.StatusOK {
		t.Fatalf("unauthenticated path-style list must fail, got %d", pathRec.Code)
	}

	// Root Bearer can list after Host rewrite (root skips audience/RBAC).
	okRec := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodGet, "/c1", nil)
	okReq.Host = "acct1.blob.core.windows.net"
	okReq.Header.Set("Authorization", "Bearer root-tok")
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("root host-style list status=%d body=%s", okRec.Code, okRec.Body.String())
	}

	// SharedKey for the wrong account name must not authorize Host acct1.
	badKeyRec := httptest.NewRecorder()
	badKeyReq := httptest.NewRequest(http.MethodGet, "/c1", nil)
	badKeyReq.Host = "acct1.blob.core.windows.net"
	badKeyReq.Header.Set("Authorization", "SharedKey otheracct:dGVzdA==")
	h.ServeHTTP(badKeyRec, badKeyReq)
	if badKeyRec.Code == http.StatusOK {
		t.Fatalf("SharedKey account mismatch must fail, got %d", badKeyRec.Code)
	}

	if !authn.IsPublicPath("/common/discovery/instance") {
		t.Fatal("instance discovery stays public")
	}
	inst := httptest.NewRecorder()
	h.ServeHTTP(inst, httptest.NewRequest(http.MethodGet, "/common/discovery/instance?api-version=1.1", nil))
	if inst.Code != http.StatusOK {
		t.Fatalf("instance discovery anonymous status=%d", inst.Code)
	}
}
