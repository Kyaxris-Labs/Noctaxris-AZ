package entra_test

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
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func rsaPublicPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return key, string(block)
}

func addKeyProofJWT(t *testing.T, key *rsa.PrivateKey, iss string, now time.Time) string {
	t.Helper()
	tok, err := authn.EncodeRS256JWT(key, "proof", map[string]any{
		"aud": authn.AudienceAADGraphAppID,
		"iss": iss,
		"nbf": float64(now.Unix()),
		"exp": float64(now.Add(10 * time.Minute).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func forgedAddKeyProof(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"` + authn.AudienceAADGraphAppID + `","iss":"` + iss + `"}`))
	return header + "." + payload + ".not-a-signature"
}

func TestAddKeyProofRS256AndPatchFailClosed(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599", Now: func() time.Time { return now }}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	appObj := "55555555-5555-5555-5555-555555555555"
	priv, pubPEM := rsaPublicPEM(t)

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1.0/applications/"+appObj+"/addKey",
		strings.NewReader(`{"keyCredential":{"key":`+jsonString(pubPEM)+`}}`))
	req.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first addKey %d body=%s", first.Code, first.Body.String())
	}

	forged := httptest.NewRecorder()
	freq := httptest.NewRequest(http.MethodPost, "/v1.0/applications/"+appObj+"/addKey",
		strings.NewReader(`{"keyCredential":{"key":"second"},"proof":"`+forgedAddKeyProof(appObj)+`"}`))
	freq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(forged, freq)
	if forged.Code != http.StatusBadRequest {
		t.Fatalf("forged proof %d body=%s", forged.Code, forged.Body.String())
	}

	okProof := addKeyProofJWT(t, priv, appObj, now)
	second := httptest.NewRecorder()
	sreq := httptest.NewRequest(http.MethodPost, "/v1.0/applications/"+appObj+"/addKey",
		strings.NewReader(`{"keyCredential":{"key":"second"},"proof":"`+okProof+`"}`))
	sreq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(second, sreq)
	if second.Code != http.StatusOK {
		t.Fatalf("signed proof %d body=%s", second.Code, second.Body.String())
	}

	patch := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodPatch, "/v1.0/applications/"+appObj,
		strings.NewReader(`{"keyCredentials":[{"key":"patched-without-proof"}]}`))
	preq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(patch, preq)
	if patch.Code != http.StatusBadRequest {
		t.Fatalf("patch without proof %d body=%s", patch.Code, patch.Body.String())
	}

	patchOK := httptest.NewRecorder()
	proof2 := addKeyProofJWT(t, priv, appObj, now)
	pok := httptest.NewRequest(http.MethodPatch, "/v1.0/applications/"+appObj,
		strings.NewReader(`{"displayName":"Lab App","keyCredentials":[{"key":"patched"}],"proof":"`+proof2+`"}`))
	pok.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(patchOK, pok)
	if patchOK.Code != http.StatusOK {
		t.Fatalf("patch with proof %d body=%s", patchOK.Code, patchOK.Body.String())
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
