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
)

func TestEmailAuthErrorsAndMissingDelete(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &email.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Communication/emailServices/demo"

	unauth, _ := http.NewRequest(http.MethodGet, base, nil)
	ur, _ := http.DefaultClient.Do(unauth)
	ur.Body.Close()
	if ur.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodGet, base, nil)
	miss.Header.Set("Authorization", "Bearer tok")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing get %d", mr.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, base, nil)
	del.Header.Set("Authorization", "Bearer tok")
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing delete %d", dr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, base, strings.NewReader(`{"location":"westus","properties":{"dataLocation":"United States"}}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(pr.Body)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put %d %s", pr.StatusCode, body)
	}

	get, _ := http.NewRequest(http.MethodGet, base, nil)
	get.Header.Set("Authorization", "Bearer tok")
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gr.StatusCode)
	}

	sendBad, _ := http.NewRequest(http.MethodPost, srv.URL+"/emails:send", strings.NewReader(`{}`))
	sr, _ := http.DefaultClient.Do(sendBad)
	sr.Body.Close()
	if sr.StatusCode == http.StatusOK || sr.StatusCode == http.StatusAccepted {
		t.Fatalf("send unauth %d", sr.StatusCode)
	}
}
