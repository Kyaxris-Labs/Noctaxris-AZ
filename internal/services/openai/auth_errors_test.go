package openai_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/openai"
)

func TestOpenAIAuthErrorsAndMissingDelete(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &openai.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/oai1"

	unauth, _ := http.NewRequest(http.MethodGet, base, nil)
	ur, _ := http.DefaultClient.Do(unauth)
	ur.Body.Close()
	if ur.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodDelete, base, nil)
	miss.Header.Set("Authorization", "Bearer tok")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing delete %d", mr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, base, strings.NewReader(`{"location":"eastus","properties":{"kind":"OpenAI"}}`))
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

	chatUnauth, _ := http.NewRequest(http.MethodPost, srv.URL+"/openai/oai1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	chatUnauth.Header.Set("Content-Type", "application/json")
	cr, _ := http.DefaultClient.Do(chatUnauth)
	cr.Body.Close()
	if cr.StatusCode == http.StatusOK {
		t.Fatal("chat unauth should fail")
	}

	get, _ := http.NewRequest(http.MethodGet, base+"x", nil)
	get.Header.Set("Authorization", "Bearer tok")
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing get %d", gr.StatusCode)
	}
}
