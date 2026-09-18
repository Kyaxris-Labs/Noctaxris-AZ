package entra_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestUnknownGraphPostDoesNotMutate(t *testing.T) {
	st := openStore(t)
	srv := graphServer(t, st)
	appObj := "55555555-5555-5555-5555-555555555555"

	decoyPW, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/not-a-service/applications/"+appObj+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"x"}}`))
	decoyPW.Header.Set("Content-Type", "application/json")
	pwRes, err := http.DefaultClient.Do(decoyPW)
	if err != nil {
		t.Fatal(err)
	}
	body := drain(t, pwRes)
	if pwRes.StatusCode != http.StatusNotFound {
		t.Fatalf("decoy addPassword %d %s", pwRes.StatusCode, body)
	}
	if strings.Contains(string(body), "secretText") {
		t.Fatalf("decoy mutated password: %s", body)
	}

	decoyOwner, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/users/11111111-1111-1111-1111-111111111111/owners/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/22222222-2222-2222-2222-222222222222"}`))
	decoyOwner.Header.Set("Content-Type", "application/json")
	owRes, err := http.DefaultClient.Do(decoyOwner)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, owRes)
	if owRes.StatusCode != http.StatusNotFound {
		t.Fatalf("decoy owners %d", owRes.StatusCode)
	}

	decoyRole, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/x/directoryRoles/88888888-8888-8888-8888-888888888888/members/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/22222222-2222-2222-2222-222222222222"}`))
	decoyRole.Header.Set("Content-Type", "application/json")
	roleRes, err := http.DefaultClient.Do(decoyRole)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, roleRes)
	if roleRes.StatusCode != http.StatusNotFound {
		t.Fatalf("decoy role members %d", roleRes.StatusCode)
	}

	official, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications/"+appObj+"/addPassword",
		strings.NewReader(`{"passwordCredential":{"displayName":"ok"}}`))
	official.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(official)
	if err != nil {
		t.Fatal(err)
	}
	okBody := drain(t, okRes)
	if okRes.StatusCode != http.StatusOK || !strings.Contains(string(okBody), "secretText") {
		t.Fatalf("mapped addPassword %d %s", okRes.StatusCode, okBody)
	}
}
