package eventgrid_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventgrid"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestEventGridTopicSubAndPublish(t *testing.T) {
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

	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	topicURL := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.EventGrid/topics/egt"
	req, _ := http.NewRequest(http.MethodPut, topicURL, strings.NewReader(`{"location":"eastus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("put topic %d: %s", res.StatusCode, b)
	}

	get, _ := http.NewRequest(http.MethodGet, topicURL, nil)
	get.Header.Set("Authorization", "Bearer tok")
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gres.StatusCode)
	}

	subURL := topicURL + "/providers/Microsoft.EventGrid/eventSubscriptions/es1"
	// Lab-local egress allow: use 127.0.0.1:4599 style OR allow hook via env.
	// hook.URL is random port; set allowlist.
	t.Setenv("NOCTAXRIS_AZ_HTTP_EGRESS", "1")
	t.Setenv("NOCTAXRIS_AZ_HTTP_ALLOWLIST", hook.URL)
	body := `{"properties":{"destination":{"endpointType":"WebHook","properties":{"endpointUrl":"` + hook.URL + `"}}}}`
	sreq, _ := http.NewRequest(http.MethodPut, subURL, strings.NewReader(body))
	sreq.Header.Set("Authorization", "Bearer tok")
	sreq.Header.Set("Content-Type", "application/json")
	sres, err := http.DefaultClient.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer sres.Body.Close()
	if sres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(sres.Body)
		t.Fatalf("put sub %d: %s", sres.StatusCode, b)
	}

	preq, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventgrid/egt/api/events",
		strings.NewReader(`[{"id":"1"}]`))
	preq.Header.Set("Authorization", "Bearer tok")
	preq.Header.Set("Content-Type", "application/json")
	pres, err := http.DefaultClient.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pres.Body)
		t.Fatalf("publish %d: %s", pres.StatusCode, b)
	}

	unauth, err := http.Get(topicURL)
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", unauth.StatusCode)
	}

	missing, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.EventGrid/topics/missing", nil)
	missing.Header.Set("Authorization", "Bearer tok")
	mres, err := http.DefaultClient.Do(missing)
	if err != nil {
		t.Fatal(err)
	}
	defer mres.Body.Close()
	if mres.StatusCode != http.StatusNotFound {
		t.Fatalf("missing %d", mres.StatusCode)
	}
}
