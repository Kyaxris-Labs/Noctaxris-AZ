package entra_test

import (
	"encoding/json"
	"io"
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

func tokenPOST(t *testing.T, mux http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestTokenAliasesDeviceRefreshAndWIF(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	secret := addClientSecret(t, st, config.DefaultTenantID, "sp-lab-1")
	form := "grant_type=client_credentials&client_id=sp-lab-1&client_secret=" + url.QueryEscape(secret) + "&scope=https://management.azure.com/.default"
	for _, path := range []string{
		"/common/oauth2/v2.0/token",
		"/organizations/oauth2/v2.0/token",
		"/" + config.DefaultTenantID + "/oauth2/token",
	} {
		rec := tokenPOST(t, mux, path, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		tok, _ := resp["access_token"].(string)
		if tok == "" {
			t.Fatalf("%s missing token: %#v", path, resp)
		}
		_, claims, err := authn.DecodeJWTUnverified(tok)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"tid", "oid", "sub", "appid", "azp", "iss", "aud", "ver"} {
			if authn.ClaimString(claims, k) == "" && k != "aud" {
				t.Fatalf("%s missing claim %s: %#v", path, k, claims)
			}
		}
		if claims["exp"] == nil {
			t.Fatalf("%s missing exp", path)
		}
		if authn.ClaimString(claims, "tid") != config.DefaultTenantID {
			t.Fatalf("%s tid=%v", path, claims["tid"])
		}
	}

	obo := tokenPOST(t, mux, "/common/oauth2/v2.0/token",
		"grant_type="+url.QueryEscape("urn:ietf:params:oauth:grant-type:jwt-bearer")+"&assertion=x")
	if obo.Code != http.StatusBadRequest {
		t.Fatalf("obo status=%d body=%s", obo.Code, obo.Body.String())
	}
	var oboBody map[string]any
	_ = json.Unmarshal(obo.Body.Bytes(), &oboBody)
	if oboBody["error"] != "unsupported_grant_type" {
		t.Fatalf("obo error=%#v", oboBody)
	}

	dc := tokenPOST(t, mux, "/common/oauth2/v2.0/devicecode", "client_id=sp-lab-1")
	if dc.Code != http.StatusOK {
		t.Fatalf("devicecode status=%d body=%s", dc.Code, dc.Body.String())
	}
	var dcBody map[string]any
	_ = json.Unmarshal(dc.Body.Bytes(), &dcBody)
	code, _ := dcBody["device_code"].(string)
	if code == "" {
		t.Fatalf("device_code missing: %#v", dcBody)
	}
	ex := tokenPOST(t, mux, "/common/oauth2/v2.0/token",
		"grant_type="+url.QueryEscape("urn:ietf:params:oauth:grant-type:device_code")+"&device_code="+url.QueryEscape(code))
	if ex.Code != http.StatusOK {
		t.Fatalf("device exchange status=%d body=%s", ex.Code, ex.Body.String())
	}

	pw := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=password&username=lab-admin@lab.local&password=unused")
	if pw.Code != http.StatusOK {
		t.Fatalf("password status=%d body=%s", pw.Code, pw.Body.String())
	}
	var pwBody map[string]any
	_ = json.Unmarshal(pw.Body.Bytes(), &pwBody)
	rt, _ := pwBody["refresh_token"].(string)
	if rt == "" {
		t.Fatal("refresh_token missing")
	}
	rf := tokenPOST(t, mux, "/common/oauth2/v2.0/token", "grant_type=refresh_token&refresh_token="+url.QueryEscape(rt))
	if rf.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", rf.Code, rf.Body.String())
	}

	issuer := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	if _, err := st.CreateFIC(appObj, "lab-wif", issuer, "repo:lab/app", []string{"api://AzureADTokenExchange"}, ""); err != nil {
		t.Fatal(err)
	}
	assertion, err := svc.MintLabOIDCAssertion("repo:lab/app", "api://AzureADTokenExchange")
	if err != nil {
		t.Fatal(err)
	}
	wifBody := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	wif := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", wifBody)
	if wif.Code != http.StatusOK {
		t.Fatalf("wif status=%d body=%s", wif.Code, wif.Body.String())
	}

	entraTok, _, err := svc.MintAccessToken(appID, "https://management.azure.com")
	if err != nil {
		t.Fatal(err)
	}
	badWIF := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {entraTok},
	}.Encode()
	denied := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", badWIF)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("entra assertion status=%d body=%s", denied.Code, denied.Body.String())
	}

	rows, err := st.QueryLogAnalyticsKQL(store.DefaultLogAnalyticsWorkspace, store.LogTableAADServicePrincipalSignInLogs+" | take 5")
	if err != nil || len(rows) == 0 {
		t.Fatalf("expected live sign-in rows: %v %v", rows, err)
	}
}

func TestMountLiteralTenantsDoesNotPanic(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.0/organization", nil))
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("graph organization %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/common/v2.0/.well-known/openid-configuration", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("common discovery %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func drain(t *testing.T, r *http.Response) []byte {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
