package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestLabOIDCTokenMintUsedAsFederatedAssertion(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	disc := httptest.NewRecorder()
	mux.ServeHTTP(disc, httptest.NewRequest(http.MethodGet, "/_noctaxris-az/oidc-lab/.well-known/openid-configuration", nil))
	if disc.Code != http.StatusOK {
		t.Fatalf("discovery %d %s", disc.Code, disc.Body.String())
	}
	var meta map[string]any
	if err := json.Unmarshal(disc.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	tokenURL, _ := meta["token_endpoint"].(string)
	if !strings.HasSuffix(tokenURL, "/_noctaxris-az/oidc-lab/token") {
		t.Fatalf("token_endpoint=%v", meta["token_endpoint"])
	}

	sub := "repo:org/lab-app"
	aud := "api://AzureADTokenExchange"
	form := url.Values{
		"grant_type": {"client_credentials"},
		"subject":    {sub},
		"audience":   {aud},
	}.Encode()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/oidc-lab/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("oidc token %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)
	if idToken == "" || accessToken == "" || idToken != accessToken {
		t.Fatalf("expected matching id_token and access_token: %#v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type=%v", body["token_type"])
	}
	_, claims, err := authn.DecodeJWTUnverified(idToken)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(claims, "iss") != "http://127.0.0.1:4599/_noctaxris-az/oidc-lab" {
		t.Fatalf("iss=%v", claims["iss"])
	}
	if authn.ClaimString(claims, "sub") != sub || authn.ClaimString(claims, "aud") != aud {
		t.Fatalf("claims=%#v", claims)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	if _, err := st.CreateFIC(appObj, "lab-oidc", "http://127.0.0.1:4599/_noctaxris-az/oidc-lab", sub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	wif := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {idToken},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	got := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", wif)
	if got.Code != http.StatusOK {
		t.Fatalf("wif with minted id_token %d %s", got.Code, got.Body.String())
	}
}
