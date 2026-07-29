package storage_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	listReq, err := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1/c1?comp=list", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(listReq, "acct1", key)
	listRes, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	defer listRes.Body.Close()
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("list status %d", listRes.StatusCode)
	}

	if err := st.CreateQueue("acct1", "q1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue("acct1", "q1", "peek-body"); err != nil {
		t.Fatal(err)
	}
	peekReq, err := http.NewRequest(http.MethodGet, srv.URL+"/queue/acct1/q1?peekonly=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(peekReq, "acct1", key)
	peekRes, err := http.DefaultClient.Do(peekReq)
	if err != nil {
		t.Fatal(err)
	}
	defer peekRes.Body.Close()
	if peekRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(peekRes.Body)
		t.Fatalf("peek status %d: %s", peekRes.StatusCode, body)
	}

	delReq, err := http.NewRequest(http.MethodDelete, srv.URL+"/blob/acct1/c1/hello.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(delReq, "acct1", key)
	delRes, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer delRes.Body.Close()
	if delRes.StatusCode != http.StatusAccepted {
		t.Fatalf("delete status %d", delRes.StatusCode)
	}
}

func TestListDeleteBlobAndQueuePeek(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	key, err := st.UpsertStorageAccount("sub", "rg", "acct1", "eastus", "127.0.0.1:4599")
	if err != nil {
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

	putC, _ := http.NewRequest(http.MethodPut, srv.URL+"/blob/acct1/c1", nil)
	signSharedKey(putC, "acct1", key)
	cres, err := http.DefaultClient.Do(putC)
	if err != nil {
		t.Fatal(err)
	}
	cres.Body.Close()
	if cres.StatusCode != http.StatusCreated {
		t.Fatalf("create container %d", cres.StatusCode)
	}

	putB, _ := http.NewRequest(http.MethodPut, srv.URL+"/blob/acct1/c1/a.txt", strings.NewReader("x"))
	signSharedKey(putB, "acct1", key)
	bres, err := http.DefaultClient.Do(putB)
	if err != nil {
		t.Fatal(err)
	}
	bres.Body.Close()
	if bres.StatusCode != http.StatusCreated {
		t.Fatalf("put blob %d", bres.StatusCode)
	}

	listC, _ := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1", nil)
	signSharedKey(listC, "acct1", key)
	lcres, err := http.DefaultClient.Do(listC)
	if err != nil {
		t.Fatal(err)
	}
	defer lcres.Body.Close()
	if lcres.StatusCode != http.StatusOK {
		t.Fatalf("list containers %d", lcres.StatusCode)
	}
	var containers struct {
		Containers []string `json:"containers"`
	}
	if err := json.NewDecoder(lcres.Body).Decode(&containers); err != nil {
		t.Fatal(err)
	}
	if len(containers.Containers) != 1 || containers.Containers[0] != "c1" {
		t.Fatalf("containers %#v", containers)
	}

	listB, _ := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1/c1?comp=list", nil)
	signSharedKey(listB, "acct1", key)
	lbres, err := http.DefaultClient.Do(listB)
	if err != nil {
		t.Fatal(err)
	}
	defer lbres.Body.Close()
	var blobs struct {
		Blobs []string `json:"blobs"`
	}
	if err := json.NewDecoder(lbres.Body).Decode(&blobs); err != nil {
		t.Fatal(err)
	}
	if len(blobs.Blobs) != 1 || blobs.Blobs[0] != "a.txt" {
		t.Fatalf("blobs %#v", blobs)
	}

	delB, _ := http.NewRequest(http.MethodDelete, srv.URL+"/blob/acct1/c1/a.txt", nil)
	signSharedKey(delB, "acct1", key)
	dbres, err := http.DefaultClient.Do(delB)
	if err != nil {
		t.Fatal(err)
	}
	dbres.Body.Close()
	if dbres.StatusCode != http.StatusAccepted {
		t.Fatalf("delete blob %d", dbres.StatusCode)
	}

	delC, _ := http.NewRequest(http.MethodDelete, srv.URL+"/blob/acct1/c1", nil)
	signSharedKey(delC, "acct1", key)
	dcres, err := http.DefaultClient.Do(delC)
	if err != nil {
		t.Fatal(err)
	}
	dcres.Body.Close()
	if dcres.StatusCode != http.StatusAccepted {
		t.Fatalf("delete container %d", dcres.StatusCode)
	}

	putQ, _ := http.NewRequest(http.MethodPut, srv.URL+"/queue/acct1/q1", nil)
	signSharedKey(putQ, "acct1", key)
	qres, err := http.DefaultClient.Do(putQ)
	if err != nil {
		t.Fatal(err)
	}
	qres.Body.Close()

	postM, _ := http.NewRequest(http.MethodPost, srv.URL+"/queue/acct1/q1", strings.NewReader(`{"MessageText":"peek-me"}`))
	signSharedKey(postM, "acct1", key)
	pmres, err := http.DefaultClient.Do(postM)
	if err != nil {
		t.Fatal(err)
	}
	pmres.Body.Close()

	peek, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acct1/q1?peekonly=true", nil)
	signSharedKey(peek, "acct1", key)
	pres, err := http.DefaultClient.Do(peek)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pres.Body)
		t.Fatalf("peek %d: %s", pres.StatusCode, body)
	}
	var msg map[string]string
	if err := json.NewDecoder(pres.Body).Decode(&msg); err != nil {
		t.Fatal(err)
	}
	if msg["MessageText"] != "peek-me" {
		t.Fatalf("peek body %#v", msg)
	}

	peek2, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acct1/q1?peekonly=true", nil)
	signSharedKey(peek2, "acct1", key)
	p2res, err := http.DefaultClient.Do(peek2)
	if err != nil {
		t.Fatal(err)
	}
	defer p2res.Body.Close()
	var msg2 map[string]string
	_ = json.NewDecoder(p2res.Body).Decode(&msg2)
	if msg2["MessageText"] != "peek-me" {
		t.Fatalf("second peek should leave message: %#v", msg2)
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
