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
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestMintAccessTokenEmptyAudienceDoesNotDefaultARM(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}

	tok, _, err := svc.MintAccessToken("sp-lab-1", "")
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := authn.DecodeJWTUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if aud := authn.ClaimString(claims, "aud"); aud != "" {
		t.Fatalf("empty audience must not default; got aud=%q", aud)
	}
	p := authn.Principal{ID: "x", Audiences: authn.ClaimAudiences(claims)}
	if p.AllowsARM() {
		t.Fatal("empty aud must not allow ARM")
	}

	armTok, _, err := svc.MintAccessToken("sp-lab-1", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	_, armClaims, err := authn.DecodeJWTUnverified(armTok)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(armClaims, "aud") != authn.AudienceARM {
		t.Fatalf("explicit ARM aud=%v", armClaims["aud"])
	}
}

func TestClientCredentialsOIDIsServicePrincipalObjectID(t *testing.T) {
	st := openStore(t)
	svc, mux := newEntraMux(t, st)
	seededApp := "66666666-6666-6666-6666-666666666666"
	seededSP := "77777777-7777-7777-7777-777777777777"
	secret := addClientSecret(t, st, config.DefaultTenantID, seededApp)

	rec := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=client_credentials&client_id="+seededApp+"&client_secret="+url.QueryEscape(secret)+"&scope=https://graph.microsoft.com/.default")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	tok, _ := resp["access_token"].(string)
	_, claims, err := authn.DecodeJWTUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(claims, "oid") != seededSP {
		t.Fatalf("oid=%q want SP object id %q", claims["oid"], seededSP)
	}
	if authn.ClaimString(claims, "appid") != seededApp || authn.ClaimString(claims, "azp") != seededApp {
		t.Fatalf("appid/azp=%q/%q want %q", claims["appid"], claims["azp"], seededApp)
	}
	_ = svc
}

func TestConditionalAccessBlocksWhenClientIDOmitted(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	graph := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	body := `{
		"displayName":"ua-gate-all",
		"state":"enabled",
		"conditions":{
			"applications":{"includeApplications":["password-client"]},
			"userAgents":{"include":["LabAgent/1.0"]}
		}
	}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1.0/identity/conditionalAccess/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	graph.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create CA %d body=%s", rec.Code, rec.Body.String())
	}

	okReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=password&username=lab-user@lab.local&password="+url.QueryEscape(store.SeededLabUserPassword)+"&scope=https://graph.microsoft.com/.default&client_id=password-client"))
	okReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okReq.Header.Set("User-Agent", "LabAgent/1.0")
	okRec := httptest.NewRecorder()
	mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("matching UA with client_id %d %s", okRec.Code, okRec.Body.String())
	}

	omit := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=password&username=lab-user@lab.local&password="+url.QueryEscape(store.SeededLabUserPassword)+"&scope=https://graph.microsoft.com/.default"))
	omit.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	omit.Header.Set("User-Agent", "OtherAgent/9.9")
	omitRec := httptest.NewRecorder()
	mux.ServeHTTP(omitRec, omit)
	if omitRec.Code != http.StatusBadRequest || !strings.Contains(omitRec.Body.String(), "AADSTS53003") {
		t.Fatalf("omitted client_id must still hit CA: %d %s", omitRec.Code, omitRec.Body.String())
	}
}

func TestFederatedAssertionRequiresClientID(t *testing.T) {
	st := openStore(t)
	svc, mux := newEntraMux(t, st)
	issuer := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	aud := "api://AzureADTokenExchange"
	sub := "repo:org/needs-client"
	seededObj := "55555555-5555-5555-5555-555555555555"
	if _, err := st.CreateFIC(seededObj, "fic", issuer, sub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	assertion, err := svc.MintLabOIDCAssertion(sub, aud)
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	rec := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", body)
	if rec.Code == http.StatusOK {
		t.Fatalf("missing client_id must not mint: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "client_id") {
		t.Fatalf("expected client_id error: %s", rec.Body.String())
	}
	assertWIF(t, svc, mux, "66666666-6666-6666-6666-666666666666", sub, true)
}

func TestRefreshTokenCannotSwitchAudience(t *testing.T) {
	st := openStore(t)
	svc, mux := newEntraMux(t, st)
	_ = svc

	form := "grant_type=password&username=lab-user@lab.local&password=" + url.QueryEscape(store.SeededLabUserPassword) +
		"&scope=https://graph.microsoft.com/.default&client_id=refresh-client"
	rec := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("password grant %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	rt, _ := resp["refresh_token"].(string)
	if rt == "" {
		t.Fatal("missing refresh_token")
	}

	same := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rt)+"&scope=https://graph.microsoft.com/.default")
	if same.Code != http.StatusOK {
		t.Fatalf("same audience refresh %d %s", same.Code, same.Body.String())
	}

	switched := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rt)+"&scope=https://management.azure.com/.default")
	if switched.Code != http.StatusBadRequest || !strings.Contains(switched.Body.String(), "audience") {
		t.Fatalf("audience switch must fail: %d %s", switched.Code, switched.Body.String())
	}

	viaResource := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/token",
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rt)+"&resource=https://management.azure.com/")
	if viaResource.Code != http.StatusBadRequest {
		t.Fatalf("resource switch must fail: %d %s", viaResource.Code, viaResource.Body.String())
	}

	keep := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(rt))
	if keep.Code != http.StatusOK {
		t.Fatalf("omitted scope should keep stored audience: %d %s", keep.Code, keep.Body.String())
	}
	var keepResp map[string]any
	_ = json.Unmarshal(keep.Body.Bytes(), &keepResp)
	tok, _ := keepResp["access_token"].(string)
	_, claims, err := authn.DecodeJWTUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if authn.ClaimString(claims, "aud") != "https://graph.microsoft.com" {
		t.Fatalf("kept aud=%v", claims["aud"])
	}
}
