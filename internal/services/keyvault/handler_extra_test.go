package keyvault_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
)

func TestKeyVaultARMSoftDeleteEncryptCert(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &keyvault.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer root-token") }

	vaultARM := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
	putV, _ := http.NewRequest(http.MethodPut, vaultARM, strings.NewReader(`{"location":"westus"}`))
	auth(putV)
	putV.Header.Set("Content-Type", "application/json")
	vres, err := http.DefaultClient.Do(putV)
	if err != nil {
		t.Fatal(err)
	}
	defer vres.Body.Close()
	if vres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(vres.Body)
		t.Fatalf("put vault %d: %s", vres.StatusCode, b)
	}
	getV, _ := http.NewRequest(http.MethodGet, vaultARM, nil)
	auth(getV)
	gv, err := http.DefaultClient.Do(getV)
	if err != nil {
		t.Fatal(err)
	}
	defer gv.Body.Close()
	if gv.StatusCode != http.StatusOK {
		t.Fatalf("get vault %d", gv.StatusCode)
	}

	putSec, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/secrets/s1",
		strings.NewReader(`{"value":"secret-a"}`))
	auth(putSec)
	putSec.Header.Set("Content-Type", "application/json")
	if res, err := http.DefaultClient.Do(putSec); err != nil {
		t.Fatal(err)
	} else {
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("put secret %d", res.StatusCode)
		}
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/keyvault/kv1/secrets/s1", nil)
	auth(del)
	dres, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer dres.Body.Close()
	if dres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dres.Body)
		t.Fatalf("delete %d: %s", dres.StatusCode, b)
	}
	getGone, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/secrets/s1", nil)
	auth(getGone)
	gg, _ := http.DefaultClient.Do(getGone)
	gg.Body.Close()
	if gg.StatusCode != http.StatusNotFound {
		t.Fatalf("gone %d", gg.StatusCode)
	}
	rec, _ := http.NewRequest(http.MethodPost, srv.URL+"/keyvault/kv1/deletedsecrets/s1/recover", nil)
	auth(rec)
	rr, err := http.DefaultClient.Do(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer rr.Body.Close()
	if rr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(rr.Body)
		t.Fatalf("recover %d: %s", rr.StatusCode, b)
	}

	putKey, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/keys/k1", strings.NewReader(`{}`))
	auth(putKey)
	putKey.Header.Set("Content-Type", "application/json")
	pk, err := http.DefaultClient.Do(putKey)
	if err != nil {
		t.Fatal(err)
	}
	defer pk.Body.Close()
	if pk.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pk.Body)
		t.Fatalf("put key %d: %s", pk.StatusCode, b)
	}
	getKey, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/keys/k1", nil)
	auth(getKey)
	gk, _ := http.DefaultClient.Do(getKey)
	gk.Body.Close()
	if gk.StatusCode != http.StatusOK {
		t.Fatalf("get key %d", gk.StatusCode)
	}

	plain := base64.StdEncoding.EncodeToString([]byte("hello-kv"))
	encReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/keyvault/kv1/keys/k1/encrypt",
		strings.NewReader(`{"value":"`+plain+`","alg":"A256GCM"}`))
	auth(encReq)
	encReq.Header.Set("Content-Type", "application/json")
	encRes, err := http.DefaultClient.Do(encReq)
	if err != nil {
		t.Fatal(err)
	}
	defer encRes.Body.Close()
	if encRes.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(encRes.Body)
		t.Fatalf("encrypt %d: %s", encRes.StatusCode, b)
	}
	var encOut struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(encRes.Body).Decode(&encOut); err != nil || encOut.Value == "" {
		t.Fatal(err)
	}
	decReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/keyvault/kv1/keys/k1/decrypt",
		strings.NewReader(`{"value":"`+encOut.Value+`"}`))
	auth(decReq)
	decReq.Header.Set("Content-Type", "application/json")
	decRes, err := http.DefaultClient.Do(decReq)
	if err != nil {
		t.Fatal(err)
	}
	defer decRes.Body.Close()
	if decRes.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(decRes.Body)
		t.Fatalf("decrypt %d: %s", decRes.StatusCode, b)
	}
	var decOut struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(decRes.Body).Decode(&decOut)
	got, _ := base64.StdEncoding.DecodeString(decOut.Value)
	if string(got) != "hello-kv" {
		t.Fatalf("plain %q", got)
	}

	putCert, _ := http.NewRequest(http.MethodPut, srv.URL+"/keyvault/kv1/certificates/c1",
		strings.NewReader(`{"value":"-----BEGIN CERTIFICATE-----\nLAB\n-----END CERTIFICATE-----","policy":{"x":1}}`))
	auth(putCert)
	putCert.Header.Set("Content-Type", "application/json")
	pc, err := http.DefaultClient.Do(putCert)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Body.Close()
	if pc.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pc.Body)
		t.Fatalf("put cert %d: %s", pc.StatusCode, b)
	}
	getCert, _ := http.NewRequest(http.MethodGet, srv.URL+"/keyvault/kv1/certificates/c1", nil)
	auth(getCert)
	gc, _ := http.DefaultClient.Do(getCert)
	gc.Body.Close()
	if gc.StatusCode != http.StatusOK {
		t.Fatalf("get cert %d", gc.StatusCode)
	}

	missVault, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/missing", nil)
	auth(missVault)
	mv, _ := http.DefaultClient.Do(missVault)
	mv.Body.Close()
	if mv.StatusCode != http.StatusNotFound {
		t.Fatalf("missing vault %d", mv.StatusCode)
	}
	badEnc, _ := http.NewRequest(http.MethodPost, srv.URL+"/keyvault/kv1/keys/k1/encrypt", strings.NewReader(`{}`))
	auth(badEnc)
	badEnc.Header.Set("Content-Type", "application/json")
	be, _ := http.DefaultClient.Do(badEnc)
	be.Body.Close()
	if be.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad encrypt %d", be.StatusCode)
	}
}
