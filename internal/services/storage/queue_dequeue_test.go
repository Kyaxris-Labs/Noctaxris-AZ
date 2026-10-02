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

func TestStorageQueueDequeueAndAuthErrors(t *testing.T) {
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

	arm := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acctq"
	put, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-token")
	put.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put %d", pr.StatusCode)
	}
	key, ok, err := st.GetStorageAccountKey("acctq")
	if err != nil || !ok {
		t.Fatal(err)
	}

	pq, _ := http.NewRequest(http.MethodPut, srv.URL+"/queue/acctq/jobs", nil)
	signSharedKey(pq, "acctq", key)
	qr, _ := http.DefaultClient.Do(pq)
	qr.Body.Close()

	empty, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/jobs", nil)
	signSharedKey(empty, "acctq", key)
	er, _ := http.DefaultClient.Do(empty)
	er.Body.Close()
	if er.StatusCode != http.StatusNoContent {
		t.Fatalf("empty dequeue %d", er.StatusCode)
	}

	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/queue/acctq/jobs",
		strings.NewReader(`{"MessageText":"payload-1"}`))
	post.Header.Set("Content-Type", "application/json")
	signSharedKey(post, "acctq", key)
	por, _ := http.DefaultClient.Do(post)
	por.Body.Close()
	if por.StatusCode != http.StatusCreated {
		t.Fatalf("enqueue %d", por.StatusCode)
	}

	badVis, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/jobs?visibilitytimeout=-1", nil)
	signSharedKey(badVis, "acctq", key)
	bvr, _ := http.DefaultClient.Do(badVis)
	bvr.Body.Close()
	if bvr.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad visibility %d", bvr.StatusCode)
	}

	dq, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/jobs?visibilitytimeout=30", nil)
	signSharedKey(dq, "acctq", key)
	dqr, err := http.DefaultClient.Do(dq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(dqr.Body)
	dqr.Body.Close()
	if dqr.StatusCode != http.StatusOK || !strings.Contains(string(body), "payload-1") {
		t.Fatalf("dequeue %d %s", dqr.StatusCode, body)
	}

	mismatch, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/jobs", nil)
	signSharedKey(mismatch, "other", key)
	mr, _ := http.DefaultClient.Do(mismatch)
	mr.Body.Close()
	if mr.StatusCode != http.StatusForbidden {
		t.Fatalf("account mismatch %d", mr.StatusCode)
	}

	noauth, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/jobs", nil)
	nr, _ := http.DefaultClient.Do(noauth)
	nr.Body.Close()
	if nr.StatusCode == http.StatusOK {
		t.Fatal("unauth should fail")
	}
}
