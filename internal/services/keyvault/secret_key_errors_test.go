package keyvault_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestKeyVaultMissingResourcesDecryptErrorsAndExportablePEM(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}
	h := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer root-token") }

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		auth(r)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	if rec := do(http.MethodPut, "/keyvault/missing/secrets/s1", `{"value":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing vault put secret %d", rec.Code)
	}
	if rec := do(http.MethodPut, "/keyvault/kv1/secrets/s1", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty secret %d", rec.Code)
	}
	if rec := do(http.MethodDelete, "/keyvault/kv1/secrets/gone", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/deletedsecrets/gone/recover", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("recover missing %d", rec.Code)
	}
	if rec := do(http.MethodPut, "/keyvault/missing/keys/k1", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing vault put key %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/keyvault/kv1/keys/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing key %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/missing/encrypt", `{"value":"QQ=="}`); rec.Code != http.StatusNotFound {
		t.Fatalf("encrypt missing %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/missing/decrypt", `{"value":"QQ=="}`); rec.Code != http.StatusNotFound {
		t.Fatalf("decrypt missing %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/keyvault/kv1/certificates/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing cert %d", rec.Code)
	}

	if rec := do(http.MethodPut, "/keyvault/kv1/keys/k1", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("put key %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/k1/decrypt", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("decrypt empty %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/k1/decrypt", `{"value":"!!!"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("decrypt bad b64 %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/k1/decrypt", `{"value":"`+base64.StdEncoding.EncodeToString([]byte("short"))+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("decrypt short %d", rec.Code)
	}
	junk := make([]byte, 48)
	_, _ = rand.Read(junk)
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/k1/decrypt", `{"value":"`+base64.StdEncoding.EncodeToString(junk)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("decrypt garbage %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/keyvault/kv1/keys/k1/encrypt", `{"value":"plain-text"}`); rec.Code != http.StatusOK {
		t.Fatalf("encrypt raw %d %s", rec.Code, rec.Body.String())
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pemJSON, _ := json.Marshal(string(pkcs1))
	body := `{"value":` + string(pemJSON) + `,"policy":{"exportable":true,"keyProperties":{"exportable":true}}}`
	if rec := do(http.MethodPut, "/keyvault/kv1/certificates/pem-import", body); rec.Code != http.StatusOK {
		t.Fatalf("exportable pem import %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/keyvault/kv1/certificates/pem-import", ""); rec.Code != http.StatusOK {
		t.Fatalf("get imported cert %d", rec.Code)
	}

	nilAuth := &keyvault.Handler{Store: st}
	nilMux := http.NewServeMux()
	nilAuth.Register(nilMux)
	arm := httptest.NewRequest(http.MethodGet, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1", nil)
	arm.Header.Set("Authorization", "Bearer root-token")
	arec := httptest.NewRecorder()
	nilMux.ServeHTTP(arec, arm)
	if arec.Code != http.StatusUnauthorized {
		t.Fatalf("nil auth arm %d", arec.Code)
	}
}
