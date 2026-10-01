package entra_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestGraphAppMutateAndFICRequireOwnerOrAdmin(t *testing.T) {
	st := openStore(t)
	appObj := "55555555-5555-5555-5555-555555555555"
	attacker := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	ownerID := "11111111-1111-1111-1111-111111111111"
	if err := st.AddOwner(appObj, ownerID, "user"); err != nil {
		t.Fatal(err)
	}

	denySrv := graphServerAs(t, st, authn.Principal{ID: attacker, Audiences: []string{authn.AudienceGraph}})
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/v1.0/applications/" + appObj + "/federatedIdentityCredentials",
			`{"name":"fic1","issuer":"http://127.0.0.1:4599/_noctaxris-az/oidc-lab","subject":"sub1","audiences":["api://AzureADTokenExchange"]}`},
		{http.MethodPatch, "/v1.0/applications/" + appObj,
			`{"keyCredentials":[{"key":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}]}`},
		{http.MethodDelete, "/v1.0/applications/" + appObj, ""},
	} {
		req, _ := http.NewRequest(tc.method, denySrv.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := drain(t, res)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, res.StatusCode, body)
		}
	}

	ownerSrv := graphServerAs(t, st, authn.Principal{ID: ownerID, Audiences: []string{authn.AudienceGraph}})
	ficReq, _ := http.NewRequest(http.MethodPost, ownerSrv.URL+"/v1.0/applications/"+appObj+"/federatedIdentityCredentials",
		strings.NewReader(`{"name":"fic-ok","issuer":"http://127.0.0.1:4599/_noctaxris-az/oidc-lab","subject":"owner-sub","audiences":["api://AzureADTokenExchange"]}`))
	ficReq.Header.Set("Content-Type", "application/json")
	ficRes, err := http.DefaultClient.Do(ficReq)
	if err != nil {
		t.Fatal(err)
	}
	ficBody := drain(t, ficRes)
	if ficRes.StatusCode != http.StatusCreated {
		t.Fatalf("owner create FIC %d %s", ficRes.StatusCode, ficBody)
	}
}
