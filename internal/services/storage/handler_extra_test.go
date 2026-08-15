package storage_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
)

func TestStorageARMAccountAndQueuePeek(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &storage.Handler{
		Store:      st,
		Auth:       &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		ListenAddr: "127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(r *http.Request) { r.Header.Set("Authorization", "Bearer root-token") }

	arm := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct2"
	put, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"westus"}`))
	auth(put)
	put.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pr.Body)
		t.Fatalf("put account %d: %s", pr.StatusCode, b)
	}
	get, _ := http.NewRequest(http.MethodGet, arm, nil)
	auth(get)
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get account %d", gr.StatusCode)
	}
	miss, _ := http.NewRequest(http.MethodGet, arm+"x", nil)
	auth(miss)
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing %d", mr.StatusCode)
	}

	key, ok, err := st.GetStorageAccountKey("acct2")
	if err != nil || !ok {
		t.Fatal(err)
	}
	pq, _ := http.NewRequest(http.MethodPut, srv.URL+"/queue/acct2/q1", nil)
	signSharedKey(pq, "acct2", key)
	qr, _ := http.DefaultClient.Do(pq)
	qr.Body.Close()
	if qr.StatusCode != http.StatusCreated && qr.StatusCode != http.StatusOK {
		t.Fatalf("put queue %d", qr.StatusCode)
	}
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/queue/acct2/q1", strings.NewReader("m1"))
	signSharedKey(post, "acct2", key)
	por, _ := http.DefaultClient.Do(post)
	por.Body.Close()
	getQ, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acct2/q1?peekonly=true", nil)
	signSharedKey(getQ, "acct2", key)
	gqr, err := http.DefaultClient.Do(getQ)
	if err != nil {
		t.Fatal(err)
	}
	defer gqr.Body.Close()
	if gqr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(gqr.Body)
		t.Fatalf("peek %d: %s", gqr.StatusCode, b)
	}
}
