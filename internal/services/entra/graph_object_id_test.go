package entra_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDeleteAndOwnersUseObjectID(t *testing.T) {
	st := openStore(t)
	srv := graphServer(t, st)
	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	spID := "77777777-7777-7777-7777-777777777777"
	owner := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"

	spOwner, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals/"+appID+"/owners/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/`+other+`"}`))
	spOwner.Header.Set("Content-Type", "application/json")
	spRes, err := http.DefaultClient.Do(spOwner)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, spRes)
	if spRes.StatusCode != http.StatusNotFound {
		t.Fatalf("SP appId owners $ref %d", spRes.StatusCode)
	}

	appOwners, err := http.Get(srv.URL + "/v1.0/applications/" + appObj + "/owners")
	if err != nil {
		t.Fatal(err)
	}
	var ownersBody map[string]any
	if err := json.Unmarshal(drain(t, appOwners), &ownersBody); err != nil {
		t.Fatal(err)
	}
	vals, _ := ownersBody["value"].([]any)
	for _, raw := range vals {
		m, _ := raw.(map[string]any)
		if m["id"] == other {
			t.Fatalf("SP appId owner landed on application %#v", ownersBody)
		}
	}

	okOwner, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals/"+spID+"/owners/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/`+owner+`"}`))
	okOwner.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(okOwner)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, okRes)
	if okRes.StatusCode != http.StatusNoContent {
		t.Fatalf("SP object id owners %d", okRes.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1.0/applications/"+appID, nil)
	delRes, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, delRes)
	if delRes.StatusCode != http.StatusNotFound {
		t.Fatalf("delete by appId %d", delRes.StatusCode)
	}
	get, err := http.Get(srv.URL + "/v1.0/applications/" + appObj)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, get)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("app still present %d", get.StatusCode)
	}
}
