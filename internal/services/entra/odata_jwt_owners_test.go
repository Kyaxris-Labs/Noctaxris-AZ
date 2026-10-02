package entra_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func TestGraphODataPagingAppOwnersAndPrivateKeyJWT(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	page := httptest.NewRecorder()
	wrap.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/v1.0/users?$top=1&$select=id,displayName", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("odata page %d %s", page.Code, page.Body.String())
	}
	var pageBody map[string]any
	if err := json.Unmarshal(page.Body.Bytes(), &pageBody); err != nil {
		t.Fatal(err)
	}
	vals, _ := pageBody["value"].([]any)
	if len(vals) != 1 {
		t.Fatalf("expected top=1 %#v", pageBody)
	}
	if pageBody["@odata.nextLink"] == nil {
		t.Fatalf("expected nextLink %#v", pageBody)
	}
	item, _ := vals[0].(map[string]any)
	if item["userPrincipalName"] != nil {
		t.Fatalf("$select leaked upn %#v", item)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	getApp := httptest.NewRecorder()
	wrap.ServeHTTP(getApp, httptest.NewRequest(http.MethodGet, "/v1.0/applications/"+appID, nil))
	if getApp.Code != http.StatusOK {
		t.Fatalf("get app %d %s", getApp.Code, getApp.Body.String())
	}
	missApp := httptest.NewRecorder()
	wrap.ServeHTTP(missApp, httptest.NewRequest(http.MethodGet, "/v1.0/applications/missing-app", nil))
	if missApp.Code != http.StatusNotFound {
		t.Fatalf("missing app %d", missApp.Code)
	}

	owners := httptest.NewRecorder()
	wrap.ServeHTTP(owners, httptest.NewRequest(http.MethodGet, "/v1.0/applications/"+appObj+"/owners", nil))
	if owners.Code != http.StatusOK {
		t.Fatalf("owners %d %s", owners.Code, owners.Body.String())
	}
	spOwners := httptest.NewRecorder()
	wrap.ServeHTTP(spOwners, httptest.NewRequest(http.MethodGet, "/v1.0/servicePrincipals/77777777-7777-7777-7777-777777777777/owners", nil))
	if spOwners.Code != http.StatusOK {
		t.Fatalf("sp owners %d", spOwners.Code)
	}
	groupOwners := httptest.NewRecorder()
	wrap.ServeHTTP(groupOwners, httptest.NewRequest(http.MethodGet, "/v1.0/groups/33333333-3333-3333-3333-333333333333/owners", nil))
	if groupOwners.Code != http.StatusOK {
		t.Fatalf("group owners %d", groupOwners.Code)
	}

	missGroup := httptest.NewRecorder()
	wrap.ServeHTTP(missGroup, httptest.NewRequest(http.MethodGet, "/v1.0/groups/missing-group", nil))
	if missGroup.Code != http.StatusNotFound {
		t.Fatalf("missing group %d", missGroup.Code)
	}
	missSP := httptest.NewRecorder()
	wrap.ServeHTTP(missSP, httptest.NewRequest(http.MethodGet, "/v1.0/servicePrincipals/missing-sp", nil))
	if missSP.Code != http.StatusNotFound {
		t.Fatalf("missing sp %d", missSP.Code)
	}
	missDev := httptest.NewRecorder()
	wrap.ServeHTTP(missDev, httptest.NewRequest(http.MethodGet, "/v1.0/devices/missing-device", nil))
	if missDev.Code != http.StatusNotFound {
		t.Fatalf("missing device %d", missDev.Code)
	}

	ca := httptest.NewRecorder()
	wrap.ServeHTTP(ca, httptest.NewRequest(http.MethodGet, "/v1.0/identity/conditionalAccess/policies", nil))
	if ca.Code != http.StatusOK {
		t.Fatalf("ca list %d", ca.Code)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))
	if _, err := st.AddKeyCredential(appObj, "application", pubPEM, "Verify", "AsymmetricX509Cert"); err != nil {
		t.Fatal(err)
	}
	tokenURL := "http://127.0.0.1:4599/" + config.DefaultTenantID + "/oauth2/v2.0/token"
	assertion, err := authn.EncodeRS256JWT(priv, "kid1", map[string]any{
		"iss": appID,
		"sub": appID,
		"aud": tokenURL,
		"nbf": float64(1),
		"exp": float64(4102444800),
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	tok := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", form)
	if tok.Code != http.StatusOK {
		t.Fatalf("private_key_jwt %d %s", tok.Code, tok.Body.String())
	}

	badAud, err := authn.EncodeRS256JWT(priv, "kid1", map[string]any{
		"iss": appID, "sub": appID, "aud": "https://example.com/token",
		"nbf": float64(1), "exp": float64(4102444800),
	})
	if err != nil {
		t.Fatal(err)
	}
	badForm := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {badAud},
	}.Encode()
	denied := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", badForm)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("bad aud %d %s", denied.Code, denied.Body.String())
	}

	labTok := httptest.NewRecorder()
	labReq := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/oidc-lab/token",
		strings.NewReader("grant_type=password&subject=s1"))
	labReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(labTok, labReq)
	if labTok.Code != http.StatusBadRequest {
		t.Fatalf("lab bad grant %d", labTok.Code)
	}
	labMiss := httptest.NewRecorder()
	labReq2 := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/oidc-lab/token",
		strings.NewReader("grant_type=client_credentials"))
	labReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(labMiss, labReq2)
	if labMiss.Code != http.StatusBadRequest {
		t.Fatalf("lab missing subject %d", labMiss.Code)
	}
	claimsTok, err := svc.MintLabOIDCAssertionClaims("sub-extra", "", map[string]any{"tid": "t1", "iss": "ignored"})
	if err != nil || claimsTok == "" {
		t.Fatalf("mint claims: %v", err)
	}

	approveBad := tokenPOST(t, mux, "/device", "user_code=NOPE&username=lab-admin@lab.local&password="+url.QueryEscape(store.SeededLabAdminPassword))
	if approveBad.Code != http.StatusBadRequest {
		t.Fatalf("bad user_code %d", approveBad.Code)
	}
	approveEmpty := tokenPOST(t, mux, "/device", "user_code=")
	if approveEmpty.Code != http.StatusBadRequest {
		t.Fatalf("empty approve %d", approveEmpty.Code)
	}
	pwEmpty := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", "grant_type=password&username=&password=")
	if pwEmpty.Code != http.StatusBadRequest {
		t.Fatalf("empty password grant %d", pwEmpty.Code)
	}
	rfEmpty := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", "grant_type=refresh_token")
	if rfEmpty.Code != http.StatusBadRequest {
		t.Fatalf("empty refresh %d", rfEmpty.Code)
	}
	dcEmpty := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type="+url.QueryEscape("urn:ietf:params:oauth:grant-type:device_code"))
	if dcEmpty.Code != http.StatusBadRequest {
		t.Fatalf("empty device_code %d", dcEmpty.Code)
	}

	iam := httptest.NewRecorder()
	wrap.ServeHTTP(iam, httptest.NewRequest(http.MethodGet, "/api/Users", nil))
	if iam.Code != http.StatusOK {
		t.Fatalf("iam users %d %s", iam.Code, iam.Body.String())
	}

	unknown := httptest.NewRecorder()
	wrap.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/v1.0/unknownResource", nil))
	if unknown.Code != http.StatusOK && unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown get %d", unknown.Code)
	}
	unknownPost := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodPost, "/v1.0/unknownResource", strings.NewReader(`{}`))
	preq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(unknownPost, preq)
	if unknownPost.Code == http.StatusInternalServerError {
		t.Fatalf("unknown post %d %s", unknownPost.Code, unknownPost.Body.String())
	}
}
