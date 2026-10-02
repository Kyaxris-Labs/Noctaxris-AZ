package rediscache_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/rediscache"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestRequireAuthzAudienceAndDeny(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	h := &rediscache.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cache/Redis"
	url := base + "/demo"

	nilAuth := &rediscache.Handler{Store: st, Auth: nil, Authz: &authz.Evaluator{Assignments: st}}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	nsrv := httptest.NewServer(nmux)
	defer nsrv.Close()
	req, _ := http.NewRequest(http.MethodGet, nsrv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cache/Redis/demo", nil)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil auth %d", res.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	pr, _ := http.DefaultClient.Do(put)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put %d", pr.StatusCode)
	}

	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	badAud, _ := http.NewRequest(http.MethodGet, url, nil)
	badAud.Header.Set("Authorization", "Bearer "+graphTok)
	bar, _ := http.DefaultClient.Do(badAud)
	bar.Body.Close()
	if bar.StatusCode != http.StatusUnauthorized && bar.StatusCode != http.StatusForbidden {
		t.Fatalf("graph aud %d", bar.StatusCode)
	}

	armTok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	deny, _ := http.NewRequest(http.MethodGet, url, nil)
	deny.Header.Set("Authorization", "Bearer "+armTok)
	dr, _ := http.DefaultClient.Do(deny)
	dr.Body.Close()
	if dr.StatusCode != http.StatusForbidden {
		t.Fatalf("deny %d", dr.StatusCode)
	}

	h2 := &rediscache.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: nil,
	}
	mux2 := http.NewServeMux()
	h2.Register(mux2)
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	rootOK, _ := http.NewRequest(http.MethodGet, srv2.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cache/Redis/demo", nil)
	rootOK.Header.Set("Authorization", "Bearer tok")
	ror, _ := http.DefaultClient.Do(rootOK)
	ror.Body.Close()
	if ror.StatusCode != http.StatusOK {
		t.Fatalf("root nil authz %d", ror.StatusCode)
	}
	nonRoot, _ := http.NewRequest(http.MethodGet, srv2.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cache/Redis/demo", nil)
	nonRoot.Header.Set("Authorization", "Bearer "+armTok)
	nr, _ := http.DefaultClient.Do(nonRoot)
	nr.Body.Close()
	if nr.StatusCode != http.StatusForbidden {
		t.Fatalf("non-root nil authz %d", nr.StatusCode)
	}
}
