package storage_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
)

func TestStorageQueueDequeueAuthFailuresAndARMErrors(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	key, err := st.UpsertStorageAccount("sub", "rg", "acctq", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	h := &storage.Handler{
		Store:      st,
		Auth:       &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz:      &authz.Evaluator{Assignments: st},
		ListenAddr: "127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pq, _ := http.NewRequest(http.MethodPut, srv.URL+"/queue/acctq/q1", nil)
	signSharedKey(pq, "acctq", key)
	qr, _ := http.DefaultClient.Do(pq)
	qr.Body.Close()
	if qr.StatusCode != http.StatusCreated && qr.StatusCode != http.StatusOK {
		t.Fatalf("put queue %d", qr.StatusCode)
	}

	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/queue/acctq/q1",
		strings.NewReader(`{"MessageText":"hello-q"}`))
	signSharedKey(post, "acctq", key)
	por, _ := http.DefaultClient.Do(post)
	por.Body.Close()
	if por.StatusCode != http.StatusCreated {
		t.Fatalf("enqueue %d", por.StatusCode)
	}

	// Dequeue (not peek) with visibilitytimeout.
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1?visibilitytimeout=30", nil)
	signSharedKey(get, "acctq", key)
	gr, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gr.Body)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("dequeue %d %s", gr.StatusCode, body)
	}
	if !strings.Contains(string(body), "hello-q") {
		t.Fatalf("body=%s", body)
	}

	empty, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1", nil)
	signSharedKey(empty, "acctq", key)
	er, _ := http.DefaultClient.Do(empty)
	er.Body.Close()
	if er.StatusCode != http.StatusNoContent {
		t.Fatalf("empty dequeue %d", er.StatusCode)
	}

	badVis, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1?visibilitytimeout=-1", nil)
	signSharedKey(badVis, "acctq", key)
	bvr, _ := http.DefaultClient.Do(badVis)
	bvr.Body.Close()
	if bvr.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad vis %d", bvr.StatusCode)
	}

	noAuth, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1", nil)
	nar, _ := http.DefaultClient.Do(noAuth)
	nar.Body.Close()
	if nar.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth %d", nar.StatusCode)
	}

	mismatch, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1", nil)
	signSharedKey(mismatch, "other", key)
	mmr, _ := http.DefaultClient.Do(mismatch)
	mmr.Body.Close()
	if mmr.StatusCode != http.StatusForbidden {
		t.Fatalf("account mismatch %d", mmr.StatusCode)
	}

	unknownAcct, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/missing/q1", nil)
	signSharedKey(unknownAcct, "missing", key)
	uar, _ := http.DefaultClient.Do(unknownAcct)
	uar.Body.Close()
	if uar.StatusCode != http.StatusNotFound && uar.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown account %d", uar.StatusCode)
	}

	// Root bearer bypasses SharedKey for data plane.
	rootGet, _ := http.NewRequest(http.MethodGet, srv.URL+"/queue/acctq/q1?peekonly=true", nil)
	rootGet.Header.Set("Authorization", "Bearer root-token")
	rgr, _ := http.DefaultClient.Do(rootGet)
	rgr.Body.Close()
	if rgr.StatusCode != http.StatusOK && rgr.StatusCode != http.StatusNoContent {
		t.Fatalf("root peek %d", rgr.StatusCode)
	}

	// ARM auth errors.
	arm := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acctq"
	noARM, _ := http.NewRequest(http.MethodGet, arm, nil)
	nar2, _ := http.DefaultClient.Do(noARM)
	nar2.Body.Close()
	if nar2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("arm no auth %d", nar2.StatusCode)
	}

	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	badAud, _ := http.NewRequest(http.MethodGet, arm, nil)
	badAud.Header.Set("Authorization", "Bearer "+graphTok)
	bar, _ := http.DefaultClient.Do(badAud)
	bar.Body.Close()
	if bar.StatusCode != http.StatusUnauthorized && bar.StatusCode != http.StatusForbidden {
		t.Fatalf("arm graph aud %d", bar.StatusCode)
	}

	armTok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	deny, _ := http.NewRequest(http.MethodGet, arm, nil)
	deny.Header.Set("Authorization", "Bearer "+armTok)
	dr, _ := http.DefaultClient.Do(deny)
	dr.Body.Close()
	if dr.StatusCode != http.StatusForbidden {
		t.Fatalf("arm deny %d", dr.StatusCode)
	}

	nilAuth := &storage.Handler{Store: st, Auth: nil, ListenAddr: "127.0.0.1:4599"}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	nsrv := httptest.NewServer(nmux)
	defer nsrv.Close()
	req, _ := http.NewRequest(http.MethodGet, nsrv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acctq", nil)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil auth arm %d", res.StatusCode)
	}
}
