package eventgrid_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventgrid"
)

func TestEventGridSubscriptionValidationRequired(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &eventgrid.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	badHook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer badHook.Close()

	topicURL := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.EventGrid/topics/egt"
	req, _ := http.NewRequest(http.MethodPut, topicURL, strings.NewReader(`{"location":"eastus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put topic %d", res.StatusCode)
	}

	t.Setenv("NOCTAXRIS_AZ_HTTP_EGRESS", "1")
	t.Setenv("NOCTAXRIS_AZ_HTTP_ALLOWLIST", badHook.URL)
	subURL := topicURL + "/providers/Microsoft.EventGrid/eventSubscriptions/es-bad"
	body := `{"properties":{"destination":{"endpointType":"WebHook","properties":{"endpointUrl":"` + badHook.URL + `"}}}}`
	sreq, _ := http.NewRequest(http.MethodPut, subURL, strings.NewReader(body))
	sreq.Header.Set("Authorization", "Bearer tok")
	sreq.Header.Set("Content-Type", "application/json")
	sres, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer sres.Body.Close()
	if sres.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(sres.Body)
		t.Fatalf("expected validation failure %d %s", sres.StatusCode, b)
	}

	goodHook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var events []map[string]any
		_ = json.Unmarshal(raw, &events)
		data, _ := events[0]["data"].(map[string]any)
		code, _ := data["validationCode"].(string)
		_ = json.NewEncoder(w).Encode(map[string]string{"validationResponse": code})
	}))
	defer goodHook.Close()
	t.Setenv("NOCTAXRIS_AZ_HTTP_ALLOWLIST", goodHook.URL)
	body = `{"properties":{"destination":{"endpointType":"WebHook","properties":{"endpointUrl":"` + goodHook.URL + `"}}}}`
	sreq, _ = http.NewRequest(http.MethodPut, topicURL+"/providers/Microsoft.EventGrid/eventSubscriptions/es-ok", strings.NewReader(body))
	sreq.Header.Set("Authorization", "Bearer tok")
	sreq.Header.Set("Content-Type", "application/json")
	sres, err = http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer sres.Body.Close()
	if sres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(sres.Body)
		t.Fatalf("expected validation success %d %s", sres.StatusCode, b)
	}
}
