package email_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/email"
)

func TestARMListDeleteAndSend(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &email.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Communication/emailServices"
	url := base + "/demo"
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"eastus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("put %d: %s", res.StatusCode, b)
	}
	list, _ := http.NewRequest(http.MethodGet, base, nil)
	list.Header.Set("Authorization", "Bearer tok")
	lr, _ := http.DefaultClient.Do(list)
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("list %d", lr.StatusCode)
	}
	send, _ := http.NewRequest(http.MethodPost, srv.URL+"/emails:send",
		strings.NewReader(`{"senderAddress":"noreply@lab","content":{"subject":"hi","plainText":"x"},"recipients":{"to":[{"address":"a@b.c"}]}}`))
	send.Header.Set("Authorization", "Bearer tok")
	send.Header.Set("Content-Type", "application/json")
	sr, err := http.DefaultClient.Do(send)
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Body.Close()
	if sr.StatusCode != http.StatusOK && sr.StatusCode != http.StatusAccepted && sr.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(sr.Body)
		t.Fatalf("send %d: %s", sr.StatusCode, b)
	}
	del, _ := http.NewRequest(http.MethodDelete, url, nil)
	del.Header.Set("Authorization", "Bearer tok")
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("delete %d", dr.StatusCode)
	}
}
