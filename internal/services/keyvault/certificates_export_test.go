package keyvault_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestCertificateExportableSecretSignsClientAssertion(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}

	kv := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
	}
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	kv.Register(mux)
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1.0/") {
			r = r.WithContext(authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true}))
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrap)
	defer srv.Close()
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer root-token") }

	locked, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/certificates/locked",
		strings.NewReader(`{"value":"-----BEGIN CERTIFICATE-----\nLAB\n-----END CERTIFICATE-----","policy":{"key_props":{"exportable":false}}}`))
	auth(locked)
	locked.Header.Set("Content-Type", "application/json")
	lres, err := http.DefaultClient.Do(locked)
	if err != nil {
		t.Fatal(err)
	}
	lres.Body.Close()
	if lres.StatusCode != http.StatusOK {
		t.Fatalf("put locked cert %d", lres.StatusCode)
	}
	getLocked, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/secrets/locked", nil)
	auth(getLocked)
	gl, err := http.DefaultClient.Do(getLocked)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(gl.Body)
	gl.Body.Close()
	if gl.StatusCode != http.StatusForbidden {
		t.Fatalf("non-exportable secret GET %d", gl.StatusCode)
	}

	exp, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/certificates/exportable",
		strings.NewReader(`{"policy":{"key_props":{"exportable":true}}}`))
	auth(exp)
	exp.Header.Set("Content-Type", "application/json")
	eres, err := http.DefaultClient.Do(exp)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := io.ReadAll(eres.Body)
	eres.Body.Close()
	if eres.StatusCode != http.StatusOK {
		t.Fatalf("put exportable cert %d %s", eres.StatusCode, eb)
	}

	getCer, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/certificates/exportable", nil)
	auth(getCer)
	gc, err := http.DefaultClient.Do(getCer)
	if err != nil {
		t.Fatal(err)
	}
	var cerBody map[string]any
	_ = json.NewDecoder(gc.Body).Decode(&cerBody)
	gc.Body.Close()
	cer, _ := cerBody["cer"].(string)
	if !strings.Contains(cer, "BEGIN CERTIFICATE") {
		t.Fatalf("certificate GET should stay public cer: %#v", cerBody)
	}

	getSec, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/secrets/exportable", nil)
	auth(getSec)
	gs, err := http.DefaultClient.Do(getSec)
	if err != nil {
		t.Fatal(err)
	}
	var sec struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(gs.Body).Decode(&sec); err != nil {
		t.Fatal(err)
	}
	gs.Body.Close()
	if gs.StatusCode != http.StatusOK || !strings.Contains(sec.Value, "PRIVATE KEY") {
		t.Fatalf("exportable secret %d value=%q", gs.StatusCode, sec.Value)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	keyJSON, _ := json.Marshal(sec.Value)
	add, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications/"+appObj+"/addKey",
		strings.NewReader(`{"keyCredential":{"key":`+string(keyJSON)+`}}`))
	add.Header.Set("Content-Type", "application/json")
	ares, err := http.DefaultClient.Do(add)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := io.ReadAll(ares.Body)
	ares.Body.Close()
	if ares.StatusCode != http.StatusOK {
		t.Fatalf("addKey %d %s", ares.StatusCode, ab)
	}

	priv, err := parseRSAPrivatePEM(sec.Value)
	if err != nil {
		t.Fatal(err)
	}
	tokenURL := "http://127.0.0.1:4599/" + config.DefaultTenantID + "/oauth2/v2.0/token"
	assertion, err := authn.EncodeRS256JWT(priv, "kv", map[string]any{
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
	}.Encode()
	tokReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", strings.NewReader(form))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("client_assertion %d %s", tokRec.Code, tokRec.Body.String())
	}
}

func parseRSAPrivatePEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, io.ErrUnexpectedEOF
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return key, nil
}
