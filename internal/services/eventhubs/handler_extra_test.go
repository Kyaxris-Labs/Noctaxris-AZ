package eventhubs_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
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
	capReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	auth(capReq)
	capRes, err := http.DefaultClient.Do(capReq)
	if err != nil {
		t.Fatal(err)
	}
	defer capRes.Body.Close()
	if capRes.StatusCode != http.StatusOK {
		t.Fatalf("capture %d", capRes.StatusCode)
	}
	capBody, _ := io.ReadAll(capRes.Body)
	if !strings.Contains(string(capBody), "eh-body") {
		t.Fatalf("capture body %s", capBody)
	}
	one, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents/1", nil)
	auth(one)
	oneRes, err := http.DefaultClient.Do(one)
	if err != nil {
		t.Fatal(err)
	}
	oneBody, _ := io.ReadAll(oneRes.Body)
	oneRes.Body.Close()
	if oneRes.StatusCode != http.StatusOK || !strings.Contains(string(oneBody), "eh-body") {
		t.Fatalf("capture get %d %s", oneRes.StatusCode, oneBody)
	}
	miss, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/missing", nil)
	auth(miss)
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing %d", mr.StatusCode)
	}
}

type directoryTokens struct {
	id string
}

func (d directoryTokens) LookupAccessToken(string, time.Time) (string, bool, error) {
	if d.id == "" {
		return "", false, nil
	}
	return d.id, true, nil
}

func TestEventHubsDataPlaneRejectsDirectoryBearer(t *testing.T) {
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
		Auth: &authn.Authenticator{
			RootClientID:    "r",
			RootAccessToken: "tok",
			Tokens:          directoryTokens{id: "lab-admin"},
		},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	user := func(r *http.Request) { r.Header.Set("Authorization", "Bearer directory-token") }
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/ns1/hubs/hub1/messages", strings.NewReader("nope"))
	user(post)
	pr, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusForbidden {
		t.Fatalf("directory send %d", pr.StatusCode)
	}

	gm, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/messages", nil)
	user(gm)
	gmr, err := http.DefaultClient.Do(gm)
	if err != nil {
		t.Fatal(err)
	}
	gmr.Body.Close()
	if gmr.StatusCode != http.StatusForbidden {
		t.Fatalf("directory receive %d", gmr.StatusCode)
	}

	capReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	user(capReq)
	capRes, err := http.DefaultClient.Do(capReq)
	if err != nil {
		t.Fatal(err)
	}
	defer capRes.Body.Close()
	if capRes.StatusCode != http.StatusForbidden {
		t.Fatalf("directory capturedEvents %d", capRes.StatusCode)
	}

	unauth, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	ur, err := http.DefaultClient.Do(unauth)
	if err != nil {
		t.Fatal(err)
	}
	ur.Body.Close()
	if ur.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer capturedEvents %d", ur.StatusCode)
	}
}

func TestEventHubsCapturedEventsAuthorizedReader(t *testing.T) {
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
	readerID := "eh-reader"
	h := &eventhubs.Handler{
		Store: st,
		Auth: &authn.Authenticator{
			RootClientID:    "r",
			RootAccessToken: "tok",
			Tokens:          directoryTokens{id: readerID},
		},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	authRoot := func(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }

	ns := srv.URL + "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
	req, _ := http.NewRequest(http.MethodPut, ns, strings.NewReader(`{"location":"eastus"}`))
	authRoot(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("put ns %d", res.StatusCode)
	}
	hub, _ := http.NewRequest(http.MethodPut, ns+"/eventhubs/hub1", strings.NewReader(`{}`))
	authRoot(hub)
	hr, _ := http.DefaultClient.Do(hub)
	hr.Body.Close()
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/eventhubs/ns1/hubs/hub1/messages?partition=0", strings.NewReader("captured-lab"))
	authRoot(post)
	pr, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusCreated {
		t.Fatalf("post %d", pr.StatusCode)
	}

	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/eh-ra",
		Scope:            "/subscriptions/s/resourceGroups/rg",
		RoleDefinitionID: authz.RoleReader,
		PrincipalID:      readerID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}

	capReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	capReq.Header.Set("Authorization", "Bearer directory-token")
	capRes, err := http.DefaultClient.Do(capReq)
	if err != nil {
		t.Fatal(err)
	}
	capRes.Body.Close()
	if capRes.StatusCode != http.StatusForbidden {
		t.Fatalf("reader capturedEvents expected 403, got %d", capRes.StatusCode)
	}

	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/eh-recv",
		Scope:            "/subscriptions/s/resourceGroups/rg",
		RoleDefinitionID: authz.RoleEventHubsDataReceiver,
		PrincipalID:      readerID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}
	recvReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	recvReq.Header.Set("Authorization", "Bearer directory-token")
	recvRes, err := http.DefaultClient.Do(recvReq)
	if err != nil {
		t.Fatal(err)
	}
	defer recvRes.Body.Close()
	if recvRes.StatusCode != http.StatusOK {
		t.Fatalf("data receiver capturedEvents %d", recvRes.StatusCode)
	}
	capBody, _ := io.ReadAll(recvRes.Body)
	if !strings.Contains(string(capBody), "captured-lab") {
		t.Fatalf("data receiver capture body %s", capBody)
	}

	outsider := &eventhubs.Handler{
		Store: st,
		Auth: &authn.Authenticator{
			RootClientID:    "r",
			RootAccessToken: "tok",
			Tokens:          directoryTokens{id: "not-assigned"},
		},
		Authz: &authz.Evaluator{Assignments: st},
	}
	denyMux := http.NewServeMux()
	outsider.Register(denyMux)
	denySrv := httptest.NewServer(denyMux)
	defer denySrv.Close()
	bad, _ := http.NewRequest(http.MethodGet, denySrv.URL+"/eventhubs/ns1/hubs/hub1/capturedEvents", nil)
	bad.Header.Set("Authorization", "Bearer directory-token")
	br, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	br.Body.Close()
	if br.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider capturedEvents %d", br.StatusCode)
	}
}
