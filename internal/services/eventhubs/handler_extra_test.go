package eventhubs_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEventHubsHubMessagesAndGet(t *testing.T) {
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
	h := &eventhubs.Handler{Store: st, Auth: &authn.Authenticator{RootClientID: "r", RootAccessToken: "tok"}}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }

	ns := srv.URL + "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
	req, _ := http.NewRequest(http.MethodPut, ns, strings.NewReader(`{"location":"eastus"}`))
	auth(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	get, _ := http.NewRequest(http.MethodGet, ns, nil)
	auth(get)
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != 200 {
		t.Fatalf("get ns %d", gr.StatusCode)
	}
	hub, _ := http.NewRequest(http.MethodPut, ns+"/eventhubs/hub1", strings.NewReader(`{}`))
	auth(hub)
	hr, _ := http.DefaultClient.Do(hub)
	hr.Body.Close()
	if hr.StatusCode != 200 {
		t.Fatalf("hub %d", hr.StatusCode)
	}
	cg, _ := http.NewRequest(http.MethodPut, ns+"/eventhubs/hub1/consumergroups/$Default", strings.NewReader(`{}`))
	auth(cg)
	cr, _ := http.DefaultClient.Do(cg)
	cr.Body.Close()
	if cr.StatusCode != 200 {
		t.Fatalf("cg %d", cr.StatusCode)
	}
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/ns1/hubs/hub1/messages?partition=0", strings.NewReader("eh-body"))
	auth(post)
	pr, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusCreated {
		t.Fatalf("post %d", pr.StatusCode)
	}
	gm, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/messages?partition=0", nil)
	auth(gm)
	gmr, err := http.DefaultClient.Do(gm)
	if err != nil {
		t.Fatal(err)
	}
	defer gmr.Body.Close()
	if gmr.StatusCode != 200 {
		t.Fatalf("get msg %d", gmr.StatusCode)
	}
	b, _ := io.ReadAll(gmr.Body)
	if string(b) != "eh-body" {
		t.Fatalf("%q", b)
	}
	empty, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/messages", nil)
	auth(empty)
	er, _ := http.DefaultClient.Do(empty)
	er.Body.Close()
	if er.StatusCode != http.StatusNoContent {
		t.Fatalf("empty %d", er.StatusCode)
	}
	miss, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/missing", nil)
	auth(miss)
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing %d", mr.StatusCode)
	}
}
