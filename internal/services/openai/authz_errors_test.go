package openai_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/openai"
)

func TestOpenAIAuthzErrorsNotFoundAndChatValidation(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	_ = st.EnsureRoot("tid", "sub", "root")

	h := &openai.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts"
	url := base + "/acct1"

	noAuth, _ := http.NewRequest(http.MethodGet, url, nil)
	nr, _ := http.DefaultClient.Do(noAuth)
	nr.Body.Close()
	if nr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth %d", nr.StatusCode)
	}

	nilAuth := &openai.Handler{Store: st, Auth: nil, Authz: &authz.Evaluator{Assignments: st}}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	nsrv := httptest.NewServer(nmux)
	defer nsrv.Close()
	req, _ := http.NewRequest(http.MethodGet, nsrv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/x", nil)
	nr2, _ := http.DefaultClient.Do(req)
	nr2.Body.Close()
	if nr2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil auth %d", nr2.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"westus","properties":{"sku":"S0"}}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put %d", pr.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, url, nil)
	get.Header.Set("Authorization", "Bearer tok")
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gr.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodGet, base+"/missing", nil)
	miss.Header.Set("Authorization", "Bearer tok")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing get %d", mr.StatusCode)
	}

	delMiss, _ := http.NewRequest(http.MethodDelete, base+"/missing", nil)
	delMiss.Header.Set("Authorization", "Bearer tok")
	dmr, _ := http.DefaultClient.Do(delMiss)
	dmr.Body.Close()
	if dmr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing delete %d", dmr.StatusCode)
	}

	chatMiss, _ := http.NewRequest(http.MethodPost, srv.URL+"/openai/nope/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[]}`))
	chatMiss.Header.Set("Authorization", "Bearer tok")
	cmr, _ := http.DefaultClient.Do(chatMiss)
	cmr.Body.Close()
	if cmr.StatusCode != http.StatusNotFound {
		t.Fatalf("chat missing %d", cmr.StatusCode)
	}

	badModel, _ := http.NewRequest(http.MethodPost, srv.URL+"/openai/acct1/chat/completions",
		strings.NewReader(`{"model":"not-allowed","messages":[]}`))
	badModel.Header.Set("Authorization", "Bearer tok")
	badModel.Header.Set("Content-Type", "application/json")
	bmr, _ := http.DefaultClient.Do(badModel)
	body, _ := io.ReadAll(bmr.Body)
	bmr.Body.Close()
	if bmr.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad model %d %s", bmr.StatusCode, body)
	}

	list, _ := http.NewRequest(http.MethodGet, base, nil)
	list.Header.Set("Authorization", "Bearer tok")
	lr, _ := http.DefaultClient.Do(list)
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("list %d", lr.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, url, nil)
	del.Header.Set("Authorization", "Bearer tok")
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("delete %d", dr.StatusCode)
	}
}

func TestOpenAIRequireAudienceAndNilAuthzNonRoot(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	armTok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}

	h := &openai.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/demo"

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+graphTok)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		t.Fatalf("graph audience %d", res.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+armTok)
	res, _ = http.DefaultClient.Do(req)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("arm without role %d %s", res.StatusCode, b)
	}

	h2 := &openai.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
		Authz: nil,
	}
	mux2 := http.NewServeMux()
	h2.Register(mux2)
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	put, _ := http.NewRequest(http.MethodPut, srv2.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/r1",
		strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer tok")
	pr, _ := http.DefaultClient.Do(put)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("root nil authz put %d", pr.StatusCode)
	}

	// Non-root with nil Authz is rejected by RequireAuthzEvaluator.
	nobodyTok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	h3 := &openai.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: nil,
	}
	mux3 := http.NewServeMux()
	h3.Register(mux3)
	srv3 := httptest.NewServer(mux3)
	defer srv3.Close()
	req, _ = http.NewRequest(http.MethodGet, srv3.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/r1", nil)
	req.Header.Set("Authorization", "Bearer "+nobodyTok)
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-root nil authz %d", res.StatusCode)
	}
}
