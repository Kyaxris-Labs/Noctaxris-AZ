package entra_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestCreateServicePrincipalRequiresDirectoryWriteRole(t *testing.T) {
	st := openStore(t)

	rootSrv := graphServer(t, st)
	createApp, _ := http.NewRequest(http.MethodPost, rootSrv.URL+"/v1.0/applications",
		strings.NewReader(`{"displayName":"sp-gate-source"}`))
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
	if appID == "" {
		t.Fatalf("app fields %#v", app)
	}

	low := graphServerAs(t, st, authn.Principal{ID: "attacker", Audiences: []string{authn.AudienceGraph}})
	denyReq, _ := http.NewRequest(http.MethodPost, low.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"`+appID+`"}`))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRes, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatal(err)
	}
	denyBody := drain(t, denyRes)
	if denyRes.StatusCode != http.StatusForbidden || !strings.Contains(string(denyBody), "Authorization_RequestDenied") {
		t.Fatalf("low privilege create SP %d %s", denyRes.StatusCode, denyBody)
	}

	adminID := "22222222-2222-2222-2222-222222222222"
	aaRole := "99999999-9999-9999-9999-999999999999"
	if err := st.AddDirectoryRoleMember(aaRole, adminID); err != nil {
		t.Fatal(err)
	}
	adminSrv := graphServerAs(t, st, authn.Principal{ID: adminID, Audiences: []string{authn.AudienceGraph}})
	okReq, _ := http.NewRequest(http.MethodPost, adminSrv.URL+"/v1.0/servicePrincipals",
		strings.NewReader(`{"appId":"`+appID+`"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(okReq)
	if err != nil {
		t.Fatal(err)
	}
	okBody := drain(t, okRes)
	if okRes.StatusCode != http.StatusCreated {
		t.Fatalf("application administrator create SP %d %s", okRes.StatusCode, okBody)
	}
}
