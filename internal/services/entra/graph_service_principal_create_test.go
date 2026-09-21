package entra_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCreateServicePrincipalFromApplication(t *testing.T) {
	st := openStore(t)
	srv := graphServer(t, st)

	seededAppID := "66666666-6666-6666-6666-666666666666"
	dupReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"`+seededAppID+`"}`))
	dupReq.Header.Set("Content-Type", "application/json")
	dupRes, err := http.DefaultClient.Do(dupReq)
	if err != nil {
		t.Fatal(err)
	}
	dupBody := drain(t, dupRes)
	if dupRes.StatusCode != http.StatusBadRequest || !strings.Contains(string(dupBody), "Request_MultipleObjectsWithSameKeyValue") {
		t.Fatalf("duplicate SP %d %s", dupRes.StatusCode, dupBody)
	}

	createApp, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications",
		strings.NewReader(`{"displayName":"sp-source"}`))
	createApp.Header.Set("Content-Type", "application/json")
	appRes, err := http.DefaultClient.Do(createApp)
	if err != nil {
		t.Fatal(err)
	}
	var app map[string]any
	if err := json.Unmarshal(drain(t, appRes), &app); err != nil {
		t.Fatal(err)
	}
	if appRes.StatusCode != http.StatusCreated {
		t.Fatalf("create app %d %#v", appRes.StatusCode, app)
	}
	appID, _ := app["appId"].(string)
	objID, _ := app["id"].(string)
	if appID == "" || objID == "" {
		t.Fatalf("app fields %#v", app)
	}

	missing, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"00000000-0000-0000-0000-ffffffffffff"}`))
	missing.Header.Set("Content-Type", "application/json")
	missRes, err := http.DefaultClient.Do(missing)
	if err != nil {
		t.Fatal(err)
	}
	missBody := drain(t, missRes)
	if missRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing app %d %s", missRes.StatusCode, missBody)
	}

	spReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"`+appID+`"}`))
	spReq.Header.Set("Content-Type", "application/json")
	spRes, err := http.DefaultClient.Do(spReq)
	if err != nil {
		t.Fatal(err)
	}
	var sp map[string]any
	if err := json.Unmarshal(drain(t, spRes), &sp); err != nil {
		t.Fatal(err)
	}
	if spRes.StatusCode != http.StatusCreated {
		t.Fatalf("create SP %d %#v", spRes.StatusCode, sp)
	}
	spID, _ := sp["id"].(string)
	if spID == "" || sp["appId"] != appID {
		t.Fatalf("sp fields %#v", sp)
	}

	byApp, err := http.Get(srv.URL + "/v1.0/servicePrincipals/" + appID)
	if err != nil {
		t.Fatal(err)
	}
	var byAppBody map[string]any
	if err := json.Unmarshal(drain(t, byApp), &byAppBody); err != nil {
		t.Fatal(err)
	}
	if byApp.StatusCode != http.StatusOK || byAppBody["id"] != spID || byAppBody["appId"] != appID {
		t.Fatalf("GET by appId %d %#v", byApp.StatusCode, byAppBody)
	}

	byID, err := http.Get(srv.URL + "/v1.0/servicePrincipals/" + spID)
	if err != nil {
		t.Fatal(err)
	}
	var byIDBody map[string]any
	if err := json.Unmarshal(drain(t, byID), &byIDBody); err != nil {
		t.Fatal(err)
	}
	if byID.StatusCode != http.StatusOK || byIDBody["id"] != spID {
		t.Fatalf("GET by object id %d %#v", byID.StatusCode, byIDBody)
	}

	fromObj, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"`+objID+`"}`))
	fromObj.Header.Set("Content-Type", "application/json")
	fromObjRes, err := http.DefaultClient.Do(fromObj)
	if err != nil {
		t.Fatal(err)
	}
	fromObjBody := drain(t, fromObjRes)
	if fromObjRes.StatusCode != http.StatusBadRequest || !strings.Contains(string(fromObjBody), "Request_MultipleObjectsWithSameKeyValue") {
		t.Fatalf("create from object id after appId %d %s", fromObjRes.StatusCode, fromObjBody)
	}

	seeded, err := http.Get(srv.URL + "/v1.0/servicePrincipals/" + seededAppID)
	if err != nil {
		t.Fatal(err)
	}
	var seededBody map[string]any
	if err := json.Unmarshal(drain(t, seeded), &seededBody); err != nil {
		t.Fatal(err)
	}
	if seeded.StatusCode != http.StatusOK || seededBody["appId"] != seededAppID {
		t.Fatalf("seeded GET by appId %d %#v", seeded.StatusCode, seededBody)
	}
}
