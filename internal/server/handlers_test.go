package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestHealthReadyVersionMiddleware(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()

	s := &Server{
		cfg: config.Config{
			ListenAddr: "127.0.0.1:0", AMQPListenAddr: "127.0.0.1:0",
			RootClientID: "root", RootAccessToken: "tok",
		},
		store: st,
		audit: aud,
		authn: &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st},
		authz: &authz.Evaluator{Assignments: st},
		mux:   http.NewServeMux(),
	}
	s.registerREST()
	s.mux.HandleFunc("GET /private", func(w http.ResponseWriter, r *http.Request) {
		p, ok := authn.PrincipalFromContext(r.Context())
		if !ok || !p.IsRoot {
			t.Errorf("principal %#v", p)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	for _, path := range []string{healthPath, readyPath, versionPath} {
		res, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, res.StatusCode)
		}
		if res.Header.Get(requestIDHeader) == "" {
			t.Fatal("missing request id")
		}
	}
	for _, path := range []string{healthPath, readyPath, versionPath} {
		res, err := http.Post(hs.URL+path, "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("method %s %d", path, res.StatusCode)
		}
	}

	s2 := &Server{mux: http.NewServeMux(), authn: s.authn}
	s2.registerREST()
	rec := httptest.NewRecorder()
	s2.handleReady(rec, httptest.NewRequest(http.MethodGet, readyPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready nil store %d", rec.Code)
	}

	unauth, err := http.Get(hs.URL + "/private")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", unauth.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, hs.URL+"/private", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set(requestIDHeader, "fixed-id")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("auth %d", res.StatusCode)
	}
	if res.Header.Get(requestIDHeader) != "fixed-id" {
		t.Fatal(res.Header.Get(requestIDHeader))
	}

	if s.Authz() == nil {
		t.Fatal("authz")
	}
	p, ok := PrincipalFromContext(authn.WithPrincipal(context.Background(), authn.Principal{ID: "p"}))
	if !ok || p.ID != "p" {
		t.Fatal(p)
	}
	if RequestIDFromContext(context.Background()) != "" {
		t.Fatal("rid")
	}
	if id := newRequestID(); id == "" {
		t.Fatal("newRequestID")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.StartAMQP(ctx); err != nil {
		t.Fatal(err)
	}
	listenCtx, listenCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServeContext(listenCtx) }()
	time.Sleep(30 * time.Millisecond)
	listenCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listen exit")
	}
}

func TestNewRegistersMux(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()

	srv := New(config.Config{
		ListenAddr: "127.0.0.1:0", AMQPListenAddr: "127.0.0.1:0",
		RootClientID: "root", RootAccessToken: "tok",
		TenantID:       "00000000-0000-0000-0000-000000000001",
		SubscriptionID: "00000000-0000-0000-0000-000000000001",
	}, st, aud)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	res, err := http.Get(hs.URL + readyPath)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("ready %d", res.StatusCode)
	}
}

func TestSmokeCoreARMPaths(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sub := config.DefaultSubscriptionID
	if err := st.EnsureRoot(config.DefaultTenantID, sub, "root"); err != nil {
		t.Fatal(err)
	}
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()

	srv := New(config.Config{
		ListenAddr: "127.0.0.1:0", AMQPListenAddr: "127.0.0.1:0",
		RootClientID: "root", RootAccessToken: "tok",
		TenantID: config.DefaultTenantID, SubscriptionID: sub,
	}, st, aud)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	do := func(method, path, body, want string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, hs.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer tok")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %s status %d body %s", method, path, res.StatusCode, got)
		}
		if !strings.Contains(string(got), want) {
			t.Fatalf("%s %s body %s want substring %q", method, path, got, want)
		}
	}

	do(http.MethodGet, "/subscriptions/"+sub+"?api-version=2022-12-01", "", sub)
	do(http.MethodPut, "/subscriptions/"+sub+"/resourcegroups/rg-ci?api-version=2022-09-01",
		`{"location":"eastus"}`, "rg-ci")
	do(http.MethodPut, "/subscriptions/"+sub+"/resourcegroups/rg-ci/providers/Microsoft.Storage/storageAccounts/stci?api-version=2023-01-01",
		`{"location":"eastus","kind":"StorageV2","sku":{"name":"Standard_LRS"}}`, "stci")
	sasReq, err := http.NewRequest(http.MethodPut, hs.URL+"/blob/stci/c1/b?sig=x&se=1", strings.NewReader("nope"))
	if err != nil {
		t.Fatal(err)
	}
	sasRes, err := http.DefaultClient.Do(sasReq)
	if err != nil {
		t.Fatal(err)
	}
	sasRes.Body.Close()
	if sasRes.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned SAS %d", sasRes.StatusCode)
	}
	do(http.MethodPut, "/subscriptions/"+sub+"/resourcegroups/rg-ci/providers/Microsoft.KeyVault/vaults/kv-ci?api-version=2022-07-01",
		`{"location":"eastus","properties":{}}`, "kv-ci")
	do(http.MethodPut, "/keyvault/kv-ci/secrets/demo", `{"value":"smoke-core"}`, "demo")
}
