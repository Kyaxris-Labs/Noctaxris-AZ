package entra_test

import (
	"crypto/tls"
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

const publishedHost = "203.0.113.10:59991"

func TestDiscoveryAndLabIssuerFollowRequestHost(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{
		Store:             st,
		TenantID:          config.DefaultTenantID,
		PublicBase:        "http://127.0.0.1:4599",
		FollowRequestHost: true,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	origin := "http://" + publishedHost
	disc := getJSON(t, mux, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", publishedHost, false)
	if disc["issuer"] != origin+"/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("issuer=%v", disc["issuer"])
	}
	if disc["token_endpoint"] != origin+"/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("token_endpoint=%v", disc["token_endpoint"])
	}

	tlsDisc := getJSON(t, mux, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", publishedHost, true)
	httpsOrigin := "https://" + publishedHost
	if tlsDisc["issuer"] != httpsOrigin+"/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("tls issuer=%v", tlsDisc["issuer"])
	}
	if tlsDisc["token_endpoint"] != httpsOrigin+"/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("tls token_endpoint=%v", tlsDisc["token_endpoint"])
	}

	lab := getJSON(t, mux, "/_noctaxris-az/oidc-lab/.well-known/openid-configuration", publishedHost, false)
	if lab["issuer"] != origin+"/_noctaxris-az/oidc-lab" {
		t.Fatalf("lab issuer=%v", lab["issuer"])
	}
	if lab["token_endpoint"] != origin+"/_noctaxris-az/oidc-lab/token" {
		t.Fatalf("lab token_endpoint=%v", lab["token_endpoint"])
	}

	pinned := &entra.Service{
		Store: st, TenantID: config.DefaultTenantID, PublicBase: "https://lab.example:8443",
	}
	pinnedMux := http.NewServeMux()
	pinned.Mount(pinnedMux)
	kept := getJSON(t, pinnedMux, "/"+config.DefaultTenantID+"/v2.0/.well-known/openid-configuration", publishedHost, false)
	if kept["issuer"] != "https://lab.example:8443/"+config.DefaultTenantID+"/v2.0" {
		t.Fatalf("pinned issuer=%v", kept["issuer"])
	}
	if kept["token_endpoint"] != "https://lab.example:8443/"+config.DefaultTenantID+"/oauth2/v2.0/token" {
		t.Fatalf("pinned token_endpoint=%v", kept["token_endpoint"])
	}
}

func TestFederatedCredentialMatchesLabIssuerAcrossHosts(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{
		Store:             st,
		TenantID:          config.DefaultTenantID,
		PublicBase:        "http://127.0.0.1:4599",
		FollowRequestHost: true,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	aud := "api://AzureADTokenExchange"
	loopIss := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	pubIss := "http://" + publishedHost + "/_noctaxris-az/oidc-lab"

	subLoop := "repo:org/from-loopback"
	if _, err := st.CreateFIC(appObj, "stored-loop", loopIss, subLoop, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	pubTok := mintLabToken(t, mux, publishedHost, subLoop, aud)
	_, claims, err := authn.DecodeJWTUnverified(pubTok)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(claims, "iss") != pubIss {
		t.Fatalf("minted iss=%v", claims["iss"])
	}
	if got := exchangeFIC(t, mux, appID, pubTok); got.Code != http.StatusOK {
		t.Fatalf("loopback credential vs published iss %d %s", got.Code, got.Body.String())
	}

	subPub := "repo:org/from-public"
	if _, err := st.CreateFIC(appObj, "stored-public", pubIss, subPub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	loopTok, err := svc.MintLabOIDCAssertion(subPub, aud)
	if err != nil {
		t.Fatal(err)
	}
	_, loopClaims, err := authn.DecodeJWTUnverified(loopTok)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(loopClaims, "iss") != loopIss {
		t.Fatalf("loopback minted iss=%v", loopClaims["iss"])
	}
	if got := exchangeFIC(t, mux, appID, loopTok); got.Code != http.StatusOK {
		t.Fatalf("published credential vs loopback iss %d %s", got.Code, got.Body.String())
	}

	subOther := "repo:org/github"
	if _, err := st.CreateFIC(appObj, "github", "https://token.actions.githubusercontent.com", subOther, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	otherTok := mintLabToken(t, mux, publishedHost, subOther, aud)
	if got := exchangeFIC(t, mux, appID, otherTok); got.Code != http.StatusUnauthorized {
		t.Fatalf("unrelated issuer %d %s", got.Code, got.Body.String())
	}
}

func getJSON(t *testing.T, mux http.Handler, path, host string, useTLS bool) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %d %s", path, rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func mintLabToken(t *testing.T, mux http.Handler, host, subject, audience string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"client_credentials"},
		"subject":    {subject},
		"audience":   {audience},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/oidc-lab/token", strings.NewReader(form))
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lab token %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	tok, _ := body["id_token"].(string)
	if tok == "" {
		t.Fatalf("missing id_token %#v", body)
	}
	return tok
}

func exchangeFIC(t *testing.T, mux http.Handler, clientID, assertion string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	return tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", form)
}
