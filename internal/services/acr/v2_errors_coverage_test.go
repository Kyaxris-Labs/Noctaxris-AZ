package acr_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/acr"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestACRV2UploadErrorsOAuthAndBasicParse(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	h := &acr.Handler{
		Store:          st,
		Auth:           &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st, JWT: es},
		Authz:          &authz.Evaluator{Assignments: st},
		SubscriptionID: "sub",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	arm := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/demo"
	putARM, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"eastus"}`))
	putARM.Header.Set("Authorization", "Bearer tok")
	putARM.Header.Set("Content-Type", "application/json")
	armRes := mustDo(t, putARM)
	armRes.Body.Close()
	if armRes.StatusCode != http.StatusOK {
		t.Fatalf("arm put %d", armRes.StatusCode)
	}

	// OAuth token with root bearer.
	tokReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/token?service=containerregistry.azure.net&scope=repository:hello:pull", nil)
	tokReq.Header.Set("Authorization", "Bearer tok")
	tokRes := mustDo(t, tokReq)
	body, _ := io.ReadAll(tokRes.Body)
	tokRes.Body.Close()
	if tokRes.StatusCode != http.StatusOK {
		t.Fatalf("oauth get %d %s", tokRes.StatusCode, body)
	}

	postTok, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader("service=containerregistry.azure.net&scope=repository:hello:push,pull"))
	postTok.Header.Set("Authorization", "Bearer tok")
	postTok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ptr := mustDo(t, postTok)
	ptr.Body.Close()
	if ptr.StatusCode != http.StatusOK {
		t.Fatalf("oauth post %d", ptr.StatusCode)
	}

	// Basic auth admin:password against admin credentials if present; otherwise exercise parse failures.
	badBasic, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/token?service=containerregistry.azure.net", nil)
	badBasic.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("nouser")))
	bbr := mustDo(t, badBasic)
	bbr.Body.Close()
	if bbr.StatusCode == http.StatusOK {
		t.Fatalf("malformed basic should not succeed")
	}

	noAuthTok, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/token", nil)
	nar := mustDo(t, noAuthTok)
	nar.Body.Close()
	if nar.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oauth unauth %d", nar.StatusCode)
	}

	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	denyAud, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/token", nil)
	denyAud.Header.Set("Authorization", "Bearer "+graphTok)
	dar := mustDo(t, denyAud)
	dar.Body.Close()
	if dar.StatusCode != http.StatusForbidden && dar.StatusCode != http.StatusUnauthorized {
		t.Fatalf("graph oauth %d", dar.StatusCode)
	}

	// Upload error paths.
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/v2/hello/blobs/uploads/", nil)
	post.Header.Set("Authorization", "Bearer tok")
	postRes := mustDo(t, post)
	loc := postRes.Header.Get("Location")
	postRes.Body.Close()
	if postRes.StatusCode != http.StatusAccepted || loc == "" {
		t.Fatalf("start upload %d loc=%q", postRes.StatusCode, loc)
	}

	blob := []byte("layer-bytes")
	sum := sha256.Sum256(blob)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	noDigest, _ := http.NewRequest(http.MethodPut, srv.URL+loc, strings.NewReader(string(blob)))
	noDigest.Header.Set("Authorization", "Bearer tok")
	ndr := mustDo(t, noDigest)
	ndr.Body.Close()
	if ndr.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing digest %d", ndr.StatusCode)
	}

	badDig, _ := http.NewRequest(http.MethodPut, srv.URL+loc+"?digest=sha256:deadbeef", strings.NewReader(string(blob)))
	badDig.Header.Set("Authorization", "Bearer tok")
	bdr := mustDo(t, badDig)
	bdr.Body.Close()
	if bdr.StatusCode != http.StatusBadRequest {
		t.Fatalf("short digest %d", bdr.StatusCode)
	}

	wrongDig, _ := http.NewRequest(http.MethodPut, srv.URL+loc+"?digest="+digest[:len(digest)-1]+"a", strings.NewReader(string(blob)))
	wrongDig.Header.Set("Authorization", "Bearer tok")
	wdr := mustDo(t, wrongDig)
	wdr.Body.Close()
	if wdr.StatusCode != http.StatusBadRequest {
		t.Fatalf("digest mismatch %d", wdr.StatusCode)
	}

	unknownUUID, _ := http.NewRequest(http.MethodPut, srv.URL+"/v2/hello/blobs/uploads/not-a-real-uuid?digest="+digest, strings.NewReader(string(blob)))
	unknownUUID.Header.Set("Authorization", "Bearer tok")
	uur := mustDo(t, unknownUUID)
	uur.Body.Close()
	if uur.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown upload %d", uur.StatusCode)
	}

	okPut, _ := http.NewRequest(http.MethodPut, srv.URL+loc+"?digest="+digest, strings.NewReader(string(blob)))
	okPut.Header.Set("Authorization", "Bearer tok")
	okPut.Header.Set("Content-Type", "application/octet-stream")
	okr := mustDo(t, okPut)
	okr.Body.Close()
	if okr.StatusCode != http.StatusCreated {
		t.Fatalf("finish upload %d", okr.StatusCode)
	}
}
