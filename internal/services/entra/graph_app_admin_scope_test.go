package entra_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestApplicationAdministratorHonorsDirectoryScope(t *testing.T) {
	st := openStore(t)
	scopedApp := "55555555-5555-5555-5555-555555555555"
	otherAppID, err := st.UpsertEntraApp(config.DefaultTenantID, "", "other-app")
	if err != nil {
		t.Fatal(err)
	}
	other, ok, err := st.GetEntraApp(config.DefaultTenantID, otherAppID)
	if err != nil || !ok {
		t.Fatalf("other app ok=%v err=%v", ok, err)
	}
	adminID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	aaRole := "99999999-9999-9999-9999-999999999999"
	if err := st.PutUnifiedRoleAssignment("", adminID, aaRole, "/"+scopedApp); err != nil {
		t.Fatal(err)
	}
	if err := st.AddDirectoryRoleMember(aaRole, adminID); err != nil {
		t.Fatal(err)
	}

	adminSrv := graphServerAs(t, st, authn.Principal{ID: adminID, Audiences: []string{authn.AudienceGraph}})
	okReq, _ := http.NewRequest(http.MethodPost, adminSrv.URL+"/v1.0/applications/"+scopedApp+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"scoped"}}`))
	okReq.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(okReq)
	if err != nil {
		t.Fatal(err)
	}
	okBody := drain(t, okRes)
	if okRes.StatusCode != http.StatusOK || !strings.Contains(string(okBody), "secretText") {
		t.Fatalf("scoped addPassword %d %s", okRes.StatusCode, okBody)
	}

	denyReq, _ := http.NewRequest(http.MethodPost, adminSrv.URL+"/v1.0/applications/"+other.ObjectID+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"out-of-scope"}}`))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRes, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatal(err)
	}
	denyBody := drain(t, denyRes)
	if denyRes.StatusCode != http.StatusForbidden || !strings.Contains(string(denyBody), "Authorization_RequestDenied") {
		t.Fatalf("out-of-scope addPassword %d %s", denyRes.StatusCode, denyBody)
	}

	keyReq, _ := http.NewRequest(http.MethodPost, adminSrv.URL+"/v1.0/applications/"+other.ObjectID+"/addKey",
		strings.NewReader(`{"keyCredential":{"type":"AsymmetricX509Cert","usage":"Verify"}}`))
	keyReq.Header.Set("Content-Type", "application/json")
	keyRes, err := http.DefaultClient.Do(keyReq)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := drain(t, keyRes)
	if keyRes.StatusCode != http.StatusForbidden || !strings.Contains(string(keyBody), "Authorization_RequestDenied") {
		t.Fatalf("out-of-scope addKey %d %s", keyRes.StatusCode, keyBody)
	}

	rootSrv := graphServer(t, st)
	rootReq, _ := http.NewRequest(http.MethodPost, rootSrv.URL+"/v1.0/applications/"+other.ObjectID+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"root"}}`))
	rootReq.Header.Set("Content-Type", "application/json")
	rootRes, err := http.DefaultClient.Do(rootReq)
	if err != nil {
		t.Fatal(err)
	}
	rootBody := drain(t, rootRes)
	if rootRes.StatusCode != http.StatusOK || !strings.Contains(string(rootBody), "secretText") {
		t.Fatalf("root addPassword %d %s", rootRes.StatusCode, rootBody)
	}
}
