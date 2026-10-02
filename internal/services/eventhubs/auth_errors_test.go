package eventhubs_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEventHubsAuthErrorsAndMissingResources(t *testing.T) {
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
	h := &eventhubs.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "r", RootAccessToken: "tok"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ns := srv.URL + "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
	unauth, _ := http.NewRequest(http.MethodGet, ns, nil)
	ur, _ := http.DefaultClient.Do(unauth)
	ur.Body.Close()
	if ur.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodGet, ns, nil)
	miss.Header.Set("Authorization", "Bearer tok")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing ns %d", mr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, ns, strings.NewReader(`{"location":"westus"}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	pr, _ := http.DefaultClient.Do(put)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put ns %d", pr.StatusCode)
	}

	hubMissBadNS, _ := http.NewRequest(http.MethodPut,
		srv.URL+"/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/missing-ns/eventhubs/hubx",
		strings.NewReader(`{}`))
	hubMissBadNS.Header.Set("Authorization", "Bearer tok")
	hubMissBadNS.Header.Set("Content-Type", "application/json")
	hmr, _ := http.DefaultClient.Do(hubMissBadNS)
	hmr.Body.Close()
	if hmr.StatusCode != http.StatusNotFound {
		t.Fatalf("hub under missing ns %d", hmr.StatusCode)
	}

	hub, _ := http.NewRequest(http.MethodPut, ns+"/eventhubs/hub1", strings.NewReader(`{"properties":{"partitionCount":2}}`))
	hub.Header.Set("Authorization", "Bearer tok")
	hub.Header.Set("Content-Type", "application/json")
	hr, _ := http.DefaultClient.Do(hub)
	hr.Body.Close()
	if hr.StatusCode != http.StatusOK {
		t.Fatalf("put hub %d", hr.StatusCode)
	}

	cg, _ := http.NewRequest(http.MethodPut, ns+"/eventhubs/hub1/consumergroups/cg1", strings.NewReader(`{}`))
	cg.Header.Set("Authorization", "Bearer tok")
	cg.Header.Set("Content-Type", "application/json")
	cr, _ := http.DefaultClient.Do(cg)
	cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		t.Fatalf("put cg %d", cr.StatusCode)
	}

	postUnauth, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/ns1/hubs/hub1/messages", strings.NewReader("x"))
	pur, _ := http.DefaultClient.Do(postUnauth)
	pur.Body.Close()
	if pur.StatusCode == http.StatusCreated || pur.StatusCode == http.StatusOK {
		t.Fatalf("post unauth %d", pur.StatusCode)
	}

	getEmpty, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/messages?partition=0", nil)
	getEmpty.Header.Set("Authorization", "Bearer tok")
	ger, _ := http.DefaultClient.Do(getEmpty)
	ger.Body.Close()
	if ger.StatusCode != http.StatusNoContent && ger.StatusCode != http.StatusOK && ger.StatusCode != http.StatusNotFound {
		t.Fatalf("empty get %d", ger.StatusCode)
	}
}
