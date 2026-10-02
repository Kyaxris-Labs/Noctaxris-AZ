package email_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/email"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestEmailAuthzErrorsNotFoundAndSendValidation(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	_ = st.EnsureRoot("tid", "sub", "root")
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}

	h := &email.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Communication/emailServices"
	url := base + "/mail1"

	noAuth, _ := http.NewRequest(http.MethodGet, url, nil)
	nr, _ := http.DefaultClient.Do(noAuth)
	nr.Body.Close()
	if nr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth %d", nr.StatusCode)
	}

	nilAuth := &email.Handler{Store: st, Auth: nil}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	nsrv := httptest.NewServer(nmux)
	defer nsrv.Close()
	req, _ := http.NewRequest(http.MethodGet, nsrv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Communication/emailServices/x", nil)
	nr2, _ := http.DefaultClient.Do(req)
	nr2.Body.Close()
	if nr2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil auth %d", nr2.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"westus","properties":{"dataLocation":"United States"}}`))
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

	list, _ := http.NewRequest(http.MethodGet, base, nil)
	list.Header.Set("Authorization", "Bearer tok")
	lr, _ := http.DefaultClient.Do(list)
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("list %d", lr.StatusCode)
	}

	send, _ := http.NewRequest(http.MethodPost, srv.URL+"/emails:send",
		strings.NewReader(`{"senderAddress":"noreply@lab","content":{"subject":"s","plainText":"p"},"recipients":{"to":[{"address":"a@b.c"}]}}`))
	send.Header.Set("Authorization", "Bearer tok")
	send.Header.Set("Content-Type", "application/json")
	sr, _ := http.DefaultClient.Do(send)
	body, _ := io.ReadAll(sr.Body)
	sr.Body.Close()
	if sr.StatusCode != http.StatusAccepted && sr.StatusCode != http.StatusOK {
		t.Fatalf("send %d %s", sr.StatusCode, body)
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

	del, _ := http.NewRequest(http.MethodDelete, url, nil)
	del.Header.Set("Authorization", "Bearer tok")
	ddr, _ := http.DefaultClient.Do(del)
	ddr.Body.Close()
	if ddr.StatusCode != http.StatusOK {
		t.Fatalf("delete %d", ddr.StatusCode)
	}
}
