package storage_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestSharedKeyPutGetBlob(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	key, err := st.UpsertStorageAccount("sub", "rg", "acct1", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("acct1", "c1"); err != nil {
		t.Fatal(err)
	}

	h := &storage.Handler{
		Store:      st,
		Auth:       &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		ListenAddr: "127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	putReq, err := http.NewRequest(http.MethodPut, srv.URL+"/blob/acct1/c1/hello.txt", strings.NewReader("hello-blob"))
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(putReq, "acct1", key)
	putRes, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	defer putRes.Body.Close()
	if putRes.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putRes.Body)
		t.Fatalf("put status %d: %s", putRes.StatusCode, body)
	}

	getReq, err := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1/c1/hello.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(getReq, "acct1", key)
	getRes, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getRes.Body.Close()
	if getRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getRes.Body)
		t.Fatalf("get status %d: %s", getRes.StatusCode, body)
	}
	got, _ := io.ReadAll(getRes.Body)
	if string(got) != "hello-blob" {
		t.Fatalf("got %q", got)
	}
}

func signSharedKey(r *http.Request, account, accountKey string) {
	sts := authn.StorageStringToSign(r)
	raw, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		raw = []byte(accountKey)
	}
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	r.Header.Set("Authorization", "SharedKey "+account+":"+sig)
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 1)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
