package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func graphServer(t *testing.T, st *store.Store) *httptest.Server {
	t.Helper()
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(wrap)
	t.Cleanup(srv.Close)
	return srv
}

func TestGraphDirectoryListsPasswordOwnersAndFIC(t *testing.T) {
	st := openStore(t)
	srv := graphServer(t, st)

	org, err := http.Get(srv.URL + "/v1.0/organization")
	if err != nil {
		t.Fatal(err)
	}
	var orgBody map[string]any
	if err := json.Unmarshal(drain(t, org), &orgBody); err != nil {
		t.Fatal(err)
	}
	orgVal, _ := orgBody["value"].([]any)
	if org.StatusCode != http.StatusOK || len(orgVal) == 0 {
		t.Fatalf("organization %d %#v", org.StatusCode, orgBody)
	}

	users, err := http.Get(srv.URL + "/v1.0/users")
	if err != nil {
		t.Fatal(err)
	}
	var usersBody map[string]any
	if err := json.Unmarshal(drain(t, users), &usersBody); err != nil {
		t.Fatal(err)
	}
	userVal, _ := usersBody["value"].([]any)
	if users.StatusCode != http.StatusOK || len(userVal) < 2 {
		t.Fatalf("users %d %#v", users.StatusCode, usersBody)
	}

	groups, err := http.Get(srv.URL + "/v1.0/groups")
	if err != nil {
		t.Fatal(err)
	}
	var groupsBody map[string]any
	if err := json.Unmarshal(drain(t, groups), &groupsBody); err != nil {
		t.Fatal(err)
	}
	groupVal, _ := groupsBody["value"].([]any)
	if groups.StatusCode != http.StatusOK || len(groupVal) == 0 {
		t.Fatalf("groups %d %#v", groups.StatusCode, groupsBody)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	pwReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications/"+appObj+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"lab-secret"}}`))
	pwReq.Header.Set("Content-Type", "application/json")
	pwRes, err := http.DefaultClient.Do(pwReq)
	if err != nil {
		t.Fatal(err)
	}
	var pw map[string]any
	if err := json.Unmarshal(drain(t, pwRes), &pw); err != nil {
		t.Fatal(err)
	}
	if pwRes.StatusCode != http.StatusOK {
		t.Fatalf("addPassword %d %#v", pwRes.StatusCode, pw)
	}
	if pw["secretText"] == nil || pw["keyId"] == nil {
		t.Fatalf("addPassword fields %#v", pw)
	}

	filterURL := srv.URL + "/v1.0/applications(appId='" + appID + "')"
	filt, err := http.Get(filterURL)
	if err != nil {
		t.Fatal(err)
	}
	var app map[string]any
	if err := json.Unmarshal(drain(t, filt), &app); err != nil {
		t.Fatal(err)
	}
	if filt.StatusCode != http.StatusOK || app["appId"] != appID {
		t.Fatalf("appId filter %d %#v", filt.StatusCode, app)
	}

	ownerReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications/"+appObj+"/owners/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/11111111-1111-1111-1111-111111111111"}`))
	ownerReq.Header.Set("Content-Type", "application/json")
	ownerRes, err := http.DefaultClient.Do(ownerReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, ownerRes)
	if ownerRes.StatusCode != http.StatusNoContent {
		t.Fatalf("owners $ref %d", ownerRes.StatusCode)
	}
	owners, err := http.Get(srv.URL + "/v1.0/applications/" + appObj + "/owners")
	if err != nil {
		t.Fatal(err)
	}
	var ownersBody map[string]any
	if err := json.Unmarshal(drain(t, owners), &ownersBody); err != nil {
		t.Fatal(err)
	}
	if owners.StatusCode != http.StatusOK {
		t.Fatalf("list owners %d", owners.StatusCode)
	}
	ov, _ := ownersBody["value"].([]any)
	if len(ov) == 0 {
		t.Fatalf("owners empty %#v", ownersBody)
	}

	memberReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/groups/33333333-3333-3333-3333-333333333333/members/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/22222222-2222-2222-2222-222222222222"}`))
	memberReq.Header.Set("Content-Type", "application/json")
	memberRes, err := http.DefaultClient.Do(memberReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, memberRes)
	if memberRes.StatusCode != http.StatusNoContent {
		t.Fatalf("members $ref %d", memberRes.StatusCode)
	}

	ficReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications/"+appObj+"/federatedIdentityCredentials",
		strings.NewReader(`{"name":"gha","issuer":"http://127.0.0.1:4599/_noctaxris-az/oidc-lab","subject":"repo:org/app"}`))
	ficReq.Header.Set("Content-Type", "application/json")
	ficRes, err := http.DefaultClient.Do(ficReq)
	if err != nil {
		t.Fatal(err)
	}
	var fic map[string]any
	if err := json.Unmarshal(drain(t, ficRes), &fic); err != nil {
		t.Fatal(err)
	}
	if ficRes.StatusCode != http.StatusCreated {
		t.Fatalf("fic %d %#v", ficRes.StatusCode, fic)
	}
	if fic["issuer"] == "" || fic["subject"] == "" {
		t.Fatalf("fic fields %#v", fic)
	}
	aud, _ := fic["audiences"].([]any)
	if len(aud) == 0 || aud[0] != "api://AzureADTokenExchange" {
		t.Fatalf("fic audiences %#v", fic["audiences"])
	}

	decoy, err := http.Get(srv.URL + "/v1.0/contacts")
	if err != nil {
		t.Fatal(err)
	}
	var decoyBody map[string]any
	if err := json.Unmarshal(drain(t, decoy), &decoyBody); err != nil {
		t.Fatal(err)
	}
	if decoy.StatusCode != http.StatusOK {
		t.Fatalf("decoy %d", decoy.StatusCode)
	}
	dv, ok := decoyBody["value"].([]any)
	if !ok || len(dv) != 0 {
		t.Fatalf("decoy value %#v", decoyBody["value"])
	}

	missing, err := http.Get(srv.URL + "/v1.0/contacts/11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, missing)
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("item get %d", missing.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1.0/applications/"+appObj, nil)
	delRes, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, delRes)
	if delRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete by object id %d", delRes.StatusCode)
	}
}
