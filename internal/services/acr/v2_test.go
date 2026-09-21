package acr_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/acr"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func v2Handler(t *testing.T, st *store.Store) *acr.Handler {
	t.Helper()
	return &acr.Handler{
		Store:          st,
		Auth:           &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok", Tokens: st},
		Authz:          &authz.Evaluator{Assignments: st},
		SubscriptionID: "sub",
	}
}

func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func sha256DigestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestV2UnauthorizedWithoutBearer(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := v2Handler(t, st)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
	wa := res.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") || !strings.Contains(wa, `service="containerregistry.azure.net"`) || !strings.Contains(strings.ToLower(wa), "realm=") {
		t.Fatalf("WWW-Authenticate %q", wa)
	}
	if res.Header.Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Fatalf("api version %q", res.Header.Get("Docker-Distribution-API-Version"))
	}
}

func TestV2RootPutBlobManifestThenGet(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := v2Handler(t, st)
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

	blob := []byte("layer-bytes")
	digest := sha256DigestHex(blob)
	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/v2/hello/blobs/uploads/", nil)
	post.Header.Set("Authorization", "Bearer tok")
	postRes := mustDo(t, post)
	if postRes.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(postRes.Body)
		postRes.Body.Close()
		t.Fatalf("start upload %d %s", postRes.StatusCode, b)
	}
	loc := postRes.Header.Get("Location")
	postRes.Body.Close()
	if loc == "" {
		t.Fatal("missing Location")
	}
	putBlob, _ := http.NewRequest(http.MethodPut, srv.URL+loc+"?digest="+digest, strings.NewReader(string(blob)))
	putBlob.Header.Set("Authorization", "Bearer tok")
	putBlob.Header.Set("Content-Type", "application/octet-stream")
	blobRes := mustDo(t, putBlob)
	blobRes.Body.Close()
	if blobRes.StatusCode != http.StatusCreated {
		t.Fatalf("put blob %d", blobRes.StatusCode)
	}

	manifest := []byte(`{"schemaVersion":2,"layers":[{"digest":"` + digest + `"}]}`)
	putMan, _ := http.NewRequest(http.MethodPut, srv.URL+"/v2/hello/manifests/latest", strings.NewReader(string(manifest)))
	putMan.Header.Set("Authorization", "Bearer tok")
	putMan.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	manRes := mustDo(t, putMan)
	manRes.Body.Close()
	if manRes.StatusCode != http.StatusCreated {
		t.Fatalf("put manifest %d", manRes.StatusCode)
	}

	getBlob, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/hello/blobs/"+digest, nil)
	getBlob.Header.Set("Authorization", "Bearer tok")
	gb := mustDo(t, getBlob)
	gotBlob, _ := io.ReadAll(gb.Body)
	gb.Body.Close()
	if gb.StatusCode != http.StatusOK || string(gotBlob) != string(blob) {
		t.Fatalf("get blob %d %q", gb.StatusCode, gotBlob)
	}

	getMan, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/hello/manifests/latest", nil)
	getMan.Header.Set("Authorization", "Bearer tok")
	gm := mustDo(t, getMan)
	gotMan, _ := io.ReadAll(gm.Body)
	gm.Body.Close()
	if gm.StatusCode != http.StatusOK || string(gotMan) != string(manifest) {
		t.Fatalf("get manifest %d %q", gm.StatusCode, gotMan)
	}

	ping, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/", nil)
	ping.Header.Set("Authorization", "Bearer tok")
	pr := mustDo(t, ping)
	body, _ := io.ReadAll(pr.Body)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("ping %d %q", pr.StatusCode, body)
	}
}

func TestV2AcrPullGetNotPut(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.PutAccessToken(authn.HashToken("pull-tok"), "puller", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-acr", Scope: "/subscriptions/sub", RoleDefinitionID: authz.RoleAcrPull, PrincipalID: "puller",
	}); err != nil {
		t.Fatal(err)
	}
	h := v2Handler(t, st)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedV2Image(t, srv.URL)

	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/hello/manifests/latest", nil)
	get.Header.Set("Authorization", "Bearer pull-tok")
	gr := mustDo(t, get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("acr pull get %d", gr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, srv.URL+"/v2/hello/manifests/evil", strings.NewReader(`{"schemaVersion":2}`))
	put.Header.Set("Authorization", "Bearer pull-tok")
	put.Header.Set("Content-Type", "application/json")
	pr := mustDo(t, put)
	pr.Body.Close()
	if pr.StatusCode != http.StatusForbidden {
		t.Fatalf("acr pull put %d", pr.StatusCode)
	}

	post, _ := http.NewRequest(http.MethodPost, srv.URL+"/v2/hello/blobs/uploads/", nil)
	post.Header.Set("Authorization", "Bearer pull-tok")
	ur := mustDo(t, post)
	ur.Body.Close()
	if ur.StatusCode != http.StatusForbidden {
		t.Fatalf("acr pull upload %d", ur.StatusCode)
	}
}

func TestV2ReaderPullOnly(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.PutAccessToken(authn.HashToken("read-tok"), "reader", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-read", Scope: "/subscriptions/sub", RoleDefinitionID: authz.RoleReader, PrincipalID: "reader",
	}); err != nil {
		t.Fatal(err)
	}
	h := v2Handler(t, st)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedV2Image(t, srv.URL)

	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/hello/manifests/latest", nil)
	get.Header.Set("Authorization", "Bearer read-tok")
	gr := mustDo(t, get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("reader get %d", gr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, srv.URL+"/v2/hello/manifests/other", strings.NewReader(`{"schemaVersion":2}`))
	put.Header.Set("Authorization", "Bearer read-tok")
	pr := mustDo(t, put)
	pr.Body.Close()
	if pr.StatusCode != http.StatusForbidden {
		t.Fatalf("reader put %d", pr.StatusCode)
	}
}

func TestV2MissingDigest404(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := v2Handler(t, st)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	seedV2Image(t, srv.URL)

	missing := "sha256:" + strings.Repeat("ab", 32)
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/hello/blobs/"+missing, nil)
	get.Header.Set("Authorization", "Bearer tok")
	res := mustDo(t, get)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing blob %d %s", res.StatusCode, body)
	}

	head, _ := http.NewRequest(http.MethodHead, srv.URL+"/v2/hello/manifests/no-such-tag", nil)
	head.Header.Set("Authorization", "Bearer tok")
	hr := mustDo(t, head)
	hr.Body.Close()
	if hr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing manifest %d", hr.StatusCode)
	}
}

func TestV2Oauth2TokenAcceptedOnV2(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := v2Handler(t, st)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/token?service=containerregistry.azure.net&scope=repository:hello:pull", nil)
	req.Header.Set("Authorization", "Bearer tok")
	res := mustDo(t, req)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("oauth2 %d %s", res.StatusCode, raw)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Token == "" {
		t.Fatalf("token body %s", raw)
	}
	ping, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/", nil)
	ping.Header.Set("Authorization", "Bearer "+body.Token)
	pr := mustDo(t, ping)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("v2 with oauth token %d", pr.StatusCode)
	}
}

func seedV2Image(t *testing.T, base string) {
	t.Helper()
	arm, _ := http.NewRequest(http.MethodPut, base+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/demo", strings.NewReader(`{"location":"eastus"}`))
	arm.Header.Set("Authorization", "Bearer tok")
	arm.Header.Set("Content-Type", "application/json")
	ar := mustDo(t, arm)
	ar.Body.Close()
	if ar.StatusCode != http.StatusOK {
		t.Fatalf("seed arm %d", ar.StatusCode)
	}
	blob := []byte("layer-bytes")
	digest := sha256DigestHex(blob)
	post, _ := http.NewRequest(http.MethodPost, base+"/v2/hello/blobs/uploads/", nil)
	post.Header.Set("Authorization", "Bearer tok")
	pr := mustDo(t, post)
	loc := pr.Header.Get("Location")
	pr.Body.Close()
	putBlob, _ := http.NewRequest(http.MethodPut, base+loc+"?digest="+digest, strings.NewReader(string(blob)))
	putBlob.Header.Set("Authorization", "Bearer tok")
	br := mustDo(t, putBlob)
	br.Body.Close()
	if br.StatusCode != http.StatusCreated {
		t.Fatalf("seed blob %d", br.StatusCode)
	}
	man := []byte(`{"schemaVersion":2}`)
	putMan, _ := http.NewRequest(http.MethodPut, base+"/v2/hello/manifests/latest", strings.NewReader(string(man)))
	putMan.Header.Set("Authorization", "Bearer tok")
	mr := mustDo(t, putMan)
	mr.Body.Close()
	if mr.StatusCode != http.StatusCreated {
		t.Fatalf("seed manifest %d", mr.StatusCode)
	}
}
