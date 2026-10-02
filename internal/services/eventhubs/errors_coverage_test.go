package eventhubs_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEventHubsAuthErrorsHubWithoutNSAndCaptureID(t *testing.T) {
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
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	h := &eventhubs.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "r", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }

	ns := srv.URL + "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
	hubURL := ns + "/eventhubs/hub1"

	noAuth, _ := http.NewRequest(http.MethodGet, ns, nil)
	nr, _ := http.DefaultClient.Do(noAuth)
	nr.Body.Close()
	if nr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth %d", nr.StatusCode)
	}

	nilAuth := &eventhubs.Handler{Store: st, Auth: nil}
	nmux := http.NewServeMux()
	nilAuth.Register(nmux)
	nsrv := httptest.NewServer(nmux)
	defer nsrv.Close()
	req, _ := http.NewRequest(http.MethodGet, nsrv.URL+"/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1", nil)
	nr2, _ := http.DefaultClient.Do(req)
	nr2.Body.Close()
	if nr2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nil auth %d", nr2.StatusCode)
	}

	// Hub before namespace exists.
	hub, _ := http.NewRequest(http.MethodPut, hubURL, strings.NewReader(`{}`))
	auth(hub)
	hr, _ := http.DefaultClient.Do(hub)
	hr.Body.Close()
	if hr.StatusCode != http.StatusNotFound {
		t.Fatalf("hub without ns %d", hr.StatusCode)
	}
	cg, _ := http.NewRequest(http.MethodPut, hubURL+"/consumergroups/$Default", strings.NewReader(`{}`))
	auth(cg)
	cr, _ := http.DefaultClient.Do(cg)
	cr.Body.Close()
	if cr.StatusCode != http.StatusNotFound {
		t.Fatalf("cg without ns %d", cr.StatusCode)
	}

	putNS, _ := http.NewRequest(http.MethodPut, ns, strings.NewReader(`{"location":"eastus"}`))
	auth(putNS)
	pr, _ := http.DefaultClient.Do(putNS)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("put ns %d", pr.StatusCode)
	}
	hub, _ = http.NewRequest(http.MethodPut, hubURL, strings.NewReader(`{}`))
	auth(hub)
	hr, _ = http.DefaultClient.Do(hub)
	hr.Body.Close()
	if hr.StatusCode != http.StatusOK {
		t.Fatalf("hub %d", hr.StatusCode)
	}

	postMiss, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/missing/hubs/hub1/messages", strings.NewReader("x"))
	auth(postMiss)
	pmr, _ := http.DefaultClient.Do(postMiss)
	pmr.Body.Close()
	if pmr.StatusCode != http.StatusNotFound {
		t.Fatalf("post missing ns %d", pmr.StatusCode)
	}

	getMiss, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/missing/hubs/hub1/messages", nil)
	auth(getMiss)
	gmr, _ := http.DefaultClient.Do(getMiss)
	gmr.Body.Close()
	if gmr.StatusCode != http.StatusNotFound {
		t.Fatalf("get missing ns %d", gmr.StatusCode)
	}

	// Non-root cannot post messages (requireRoot).
	armTok, _, err := es.MintAccessToken("nobody", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/ns1/hubs/hub1/messages", strings.NewReader("x"))
	post.Header.Set("Authorization", "Bearer "+armTok)
	por, _ := http.DefaultClient.Do(post)
	por.Body.Close()
	if por.StatusCode != http.StatusForbidden {
		t.Fatalf("non-root post %d", por.StatusCode)
	}

	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	badAud, _ := http.NewRequest(http.MethodGet, ns, nil)
	badAud.Header.Set("Authorization", "Bearer "+graphTok)
	bar, _ := http.DefaultClient.Do(badAud)
	bar.Body.Close()
	if bar.StatusCode != http.StatusUnauthorized && bar.StatusCode != http.StatusForbidden {
		t.Fatalf("graph aud %d", bar.StatusCode)
	}

	deny, _ := http.NewRequest(http.MethodGet, ns, nil)
	deny.Header.Set("Authorization", "Bearer "+armTok)
	dr, _ := http.DefaultClient.Do(deny)
	dr.Body.Close()
	if dr.StatusCode != http.StatusForbidden {
		t.Fatalf("arm deny %d", dr.StatusCode)
	}

	badID, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents/0", nil)
	auth(badID)
	bir, _ := http.DefaultClient.Do(badID)
	bir.Body.Close()
	if bir.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad capture id %d", bir.StatusCode)
	}
	missCap, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents/999", nil)
	auth(missCap)
	mcr, _ := http.DefaultClient.Do(missCap)
	body, _ := io.ReadAll(mcr.Body)
	mcr.Body.Close()
	if mcr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing capture %d %s", mcr.StatusCode, body)
	}

	capMissNS, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/nope/hubs/hub1/capturedEvents", nil)
	auth(capMissNS)
	cmr, _ := http.DefaultClient.Do(capMissNS)
	cmr.Body.Close()
	if cmr.StatusCode != http.StatusForbidden {
		t.Fatalf("capture missing ns %d", cmr.StatusCode)
	}
}
