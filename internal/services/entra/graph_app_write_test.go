package entra_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func graphServerAs(t *testing.T, st *store.Store, p authn.Principal) *httptest.Server {
	t.Helper()
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(authn.WithPrincipal(r.Context(), p)))
	})
	srv := httptest.NewServer(wrap)
	t.Cleanup(srv.Close)
	return srv
}

func TestGraphAppWriteOwnersAndApplicationAdministrator(t *testing.T) {
	st := openStore(t)
	appObj := "55555555-5555-5555-5555-555555555555"
	ownerID := "11111111-1111-1111-1111-111111111111"
	adminID := "22222222-2222-2222-2222-222222222222"
	spID := "77777777-7777-7777-7777-777777777777"
	aaRole := "99999999-9999-9999-9999-999999999999"

	if err := st.AddOwner(appObj, ownerID, "user"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddDirectoryRoleMember(aaRole, adminID); err != nil {
		t.Fatal(err)
	}

	ownerSrv := graphServerAs(t, st, authn.Principal{ID: ownerID, Audiences: []string{authn.AudienceGraph}})
	pwReq, _ := http.NewRequest(http.MethodPost, ownerSrv.URL+"/v1.0/applications/"+appObj+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"owner-secret"}}`))
	pwReq.Header.Set("Content-Type", "application/json")
	pwRes, err := http.DefaultClient.Do(pwReq)
	if err != nil {
		t.Fatal(err)
	}
	pwBody := drain(t, pwRes)
	if pwRes.StatusCode != http.StatusOK || !strings.Contains(string(pwBody), "secretText") {
		t.Fatalf("owner addPassword %d %s", pwRes.StatusCode, pwBody)
	}

	spSrv := graphServerAs(t, st, authn.Principal{ID: spID, Audiences: []string{authn.AudienceGraph}})
	denyReq, _ := http.NewRequest(http.MethodPost, spSrv.URL+"/v1.0/applications/"+appObj+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"nope"}}`))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRes, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatal(err)
	}
	denyBody := drain(t, denyRes)
	if denyRes.StatusCode != http.StatusForbidden {
		t.Fatalf("unrelated SP addPassword %d %s", denyRes.StatusCode, denyBody)
	}

	adminSrv := graphServerAs(t, st, authn.Principal{ID: adminID, Audiences: []string{authn.AudienceGraph}})
	ownReq, _ := http.NewRequest(http.MethodPost, adminSrv.URL+"/v1.0/applications/"+appObj+"/owners/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/`+adminID+`"}`))
	ownReq.Header.Set("Content-Type", "application/json")
	ownRes, err := http.DefaultClient.Do(ownReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, ownRes)
	if ownRes.StatusCode != http.StatusNoContent {
		t.Fatalf("app admin owners $ref %d", ownRes.StatusCode)
	}
}
