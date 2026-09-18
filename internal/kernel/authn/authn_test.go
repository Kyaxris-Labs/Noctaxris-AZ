package authn_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

type tokenStore struct {
	id  string
	ok  bool
	err error
}

func (t tokenStore) LookupAccessToken(string, time.Time) (string, bool, error) {
	return t.id, t.ok, t.err
}

type jwtOK struct{ id string }

func (j jwtOK) VerifyAccessToken(string, time.Time) (string, bool, error) {
	return j.id, true, nil
}

func TestAuthenticateRootTokenAndPublicPaths(t *testing.T) {
	a := &authn.Authenticator{RootClientID: "root-id", RootAccessToken: "root-tok"}
	p, err := a.AuthenticateToken("root-tok")
	if err != nil || !p.IsRoot || p.ID != "root-id" {
		t.Fatalf("%+v %v", p, err)
	}
	a2 := &authn.Authenticator{RootAccessToken: "root-tok"}
	p, err = a2.AuthenticateToken("root-tok")
	if err != nil || p.ID != "root" {
		t.Fatalf("%+v %v", p, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer root-tok")
	p, err = a.AuthenticateRequest(req)
	if err != nil || !p.IsRoot {
		t.Fatal(err)
	}
	if _, err := a.AuthenticateRequest(httptest.NewRequest(http.MethodGet, "/", nil)); err != authn.ErrUnauthenticated {
		t.Fatal(err)
	}
	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.Header.Set("Authorization", "Bearer ")
	if _, err := a.AuthenticateRequest(bad); err != authn.ErrUnauthenticated {
		t.Fatal(err)
	}
	if _, err := a.AuthenticateToken("nope"); err != authn.ErrUnauthenticated {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/_noctaxris-az/health",
		"/_noctaxris-az/ready",
		"/_noctaxris-az/version",
		"/metadata/identity/oauth2/token",
		"/tenant/oauth2/v2.0/token",
		"/tenant/oauth2/token",
		"/common/oauth2/v2.0/token",
		"/common/oauth2/v2.0/devicecode",
		"/tenant/v2.0/.well-known/openid-configuration",
		"/tenant/.well-known/openid-configuration",
		"/tenant/discovery/v2.0/keys",
		"/_noctaxris-az/oidc-lab/.well-known/openid-configuration",
		"/_noctaxris-az/oidc-lab/keys",
	} {
		if !authn.IsPublicPath(path) {
			t.Fatalf("expected public %s", path)
		}
	}
	if authn.IsPublicPath("/subscriptions/x") {
		t.Fatal("private path")
	}
	if authn.IsPublicPath("/provisioningwebservice.svc") {
		t.Fatal("soap is not public")
	}
	if authn.HashToken("a") == authn.HashToken("b") {
		t.Fatal("hash collision")
	}
}

func TestAuthenticateTokenLookupAndJWT(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a := &authn.Authenticator{
		Tokens: tokenStore{id: "user1", ok: true},
		Now:    func() time.Time { return now },
	}
	p, err := a.AuthenticateToken("opaque")
	if err != nil || p.IsRoot || p.ID != "user1" {
		t.Fatalf("%+v %v", p, err)
	}

	a = &authn.Authenticator{JWT: jwtOK{id: "jwt-user"}, Now: func() time.Time { return now }}
	p, err = a.AuthenticateToken("jwt")
	if err != nil || p.ID != "jwt-user" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestJWTEncodeVerifyAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tok, err := authn.EncodeRS256JWT(key, "kid1", map[string]any{
		"oid": "oid-1",
		"exp": float64(now.Add(time.Hour).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := authn.VerifyRS256JWT(&key.PublicKey, tok, now)
	if err != nil || claims["oid"] != "oid-1" {
		t.Fatalf("%v %v", claims, err)
	}
	if authn.PrincipalFromJWTClaims(claims) != "oid-1" {
		t.Fatal(authn.PrincipalFromJWTClaims(claims))
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"sub": "s"}) != "s" {
		t.Fatal("sub")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"appid": "a"}) != "a" {
		t.Fatal("appid")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"azp": "z"}) != "z" {
		t.Fatal("azp")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{}) != "" {
		t.Fatal("empty")
	}

	expired, err := authn.EncodeRS256JWT(key, "kid1", map[string]any{"exp": float64(now.Add(-time.Hour).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authn.VerifyRS256JWT(&key.PublicKey, expired, now); err == nil {
		t.Fatal("expected expired")
	}
	if _, err := authn.VerifyRS256JWT(&key.PublicKey, "a.b", now); err == nil {
		t.Fatal("expected invalid")
	}
}

func hmacSHA256B64(key, sts string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(sts))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestSharedKeyAndSAS(t *testing.T) {
	acct, sig, ok := authn.ParseSharedKeyAuthorization("SharedKey acct:sigvalue")
	if !ok || acct != "acct" || sig != "sigvalue" {
		t.Fatalf("%q %q %v", acct, sig, ok)
	}
	if _, _, ok := authn.ParseSharedKeyAuthorization("Bearer x"); ok {
		t.Fatal("not shared key")
	}
	if _, _, ok := authn.ParseSharedKeyAuthorization("SharedKey noseparator"); ok {
		t.Fatal("bad shared key")
	}
	req := httptest.NewRequest(http.MethodGet, "/blob/c/b?sig=abc&se=2026", nil)
	sts := authn.StorageStringToSign(req)
	if sts != "GET\n/blob/c/b" {
		t.Fatalf("%q", sts)
	}
	if !authn.VerifyStorageSharedKey("not-base64-key", "hello", hmacSHA256B64("not-base64-key", "hello")) {
		t.Fatal("raw key verify")
	}
	b64key := base64.StdEncoding.EncodeToString([]byte("testkey"))
	mac := hmac.New(sha256.New, []byte("testkey"))
	_, _ = mac.Write([]byte(sts))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !authn.VerifyStorageSharedKey(b64key, sts, want) {
		t.Fatal("b64 key verify")
	}
	if !authn.HasSAS(req) {
		t.Fatal("sas")
	}
	if authn.HasSAS(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("no sas")
	}
	if authn.VerifyStorageSAS("not-base64-key", req, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("presence is not a verified SAS")
	}

	ctx := authn.WithPrincipal(context.Background(), authn.Principal{ID: "p", IsRoot: true})
	p, ok := authn.PrincipalFromContext(ctx)
	if !ok || p.ID != "p" || !p.IsRoot {
		t.Fatal(p)
	}
	_, ok = authn.PrincipalFromContext(context.Background())
	if ok {
		t.Fatal("empty ctx")
	}
}

func TestVerifyStorageSASExpiryPermissionsAndHMAC(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := base64.StdEncoding.EncodeToString([]byte("sas-account-key"))
	sign := func(method, path, sp, st, se string) *http.Request {
		t.Helper()
		u := path + "?sp=" + sp + "&se=" + se
		if st != "" {
			u = path + "?sp=" + sp + "&st=" + st + "&se=" + se
		}
		req := httptest.NewRequest(method, u, nil)
		q := req.URL.Query()
		sts := authn.StorageSASStringToSign(req)
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, raw)
		_, _ = mac.Write([]byte(sts))
		q.Set("sig", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		req.URL.RawQuery = q.Encode()
		return req
	}

	valid := sign(http.MethodGet, "/blob/acct1/c1/hello.txt", "r", "", "2026-06-02T00:00:00Z")
	if !authn.VerifyStorageSAS(key, valid, now) {
		t.Fatal("valid read SAS")
	}
	if !authn.HasSAS(valid) {
		t.Fatal("HasSAS on verified token")
	}

	expired := sign(http.MethodGet, "/blob/acct1/c1/hello.txt", "r", "", "2026-06-01T12:00:00Z")
	if authn.VerifyStorageSAS(key, expired, now) {
		t.Fatal("expiry equal to now must deny")
	}
	past := sign(http.MethodGet, "/blob/acct1/c1/hello.txt", "r", "", "2020-01-01T00:00:00Z")
	if authn.VerifyStorageSAS(key, past, now) {
		t.Fatal("elapsed se")
	}

	garbage := httptest.NewRequest(http.MethodGet, "/blob/acct1/c1/hello.txt?sig=x&se=1", nil)
	if !authn.HasSAS(garbage) {
		t.Fatal("garbage still has SAS query shape")
	}
	if authn.VerifyStorageSAS(key, garbage, now) {
		t.Fatal("unparseable se")
	}
	if authn.VerifyStorageSAS("", valid, now) {
		t.Fatal("empty account key")
	}
	if authn.VerifyStorageSAS(key, httptest.NewRequest(http.MethodGet, "/blob/acct1/c1/b?sp=r&se=2026-06-02T00:00:00Z", nil), now) {
		t.Fatal("missing sig")
	}

	write := httptest.NewRequest(http.MethodPut, "/blob/acct1/c1/hello.txt?sp=r&se=2026-06-02T00:00:00Z", nil)
	q := write.URL.Query()
	sts := authn.StorageSASStringToSign(write)
	raw, _ := base64.StdEncoding.DecodeString(key)
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(sts))
	q.Set("sig", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	write.URL.RawQuery = q.Encode()
	if authn.VerifyStorageSAS(key, write, now) {
		t.Fatal("sp=r must not allow PUT")
	}

	futureStart := sign(http.MethodGet, "/blob/acct1/c1/hello.txt", "r", "2026-06-03T00:00:00Z", "2026-06-04T00:00:00Z")
	if authn.VerifyStorageSAS(key, futureStart, now) {
		t.Fatal("st in the future")
	}

	badSig := sign(http.MethodGet, "/blob/acct1/c1/hello.txt", "r", "", "2026-06-02T00:00:00Z")
	q = badSig.URL.Query()
	q.Set("sig", "AAAA")
	badSig.URL.RawQuery = q.Encode()
	if authn.VerifyStorageSAS(key, badSig, now) {
		t.Fatal("garbage sig")
	}

	if !authn.SASPermits("l", http.MethodGet, "/blob/acct1/c1") {
		t.Fatal("list")
	}
	if authn.SASPermits("", http.MethodGet, "/blob/acct1/c1/b") {
		t.Fatal("empty sp")
	}
	if _, ok := authn.ParseSASExpiry("1"); ok {
		t.Fatal("unix-like se is not a Storage timestamp")
	}
}

func TestAudienceAllowAndHashLookup(t *testing.T) {
	graph := authn.Principal{ID: "u", Audiences: []string{authn.AudienceGraph}, Issuer: "http://127.0.0.1:4599/tid/v2.0"}
	if !graph.AllowsGraph() || graph.AllowsARM() {
		t.Fatal("graph aud")
	}
	arm := authn.Principal{ID: "u", Audiences: []string{authn.AudienceARM + "/"}, Issuer: "http://127.0.0.1:4599/tid/v2.0"}
	if !arm.AllowsARM() || arm.AllowsGraph() {
		t.Fatal("arm aud")
	}
	iss := "http://127.0.0.1:4599/tid/v2.0"
	issuerAud := authn.Principal{ID: "u", Audiences: []string{iss}, Issuer: iss}
	if issuerAud.AllowsGraph() || issuerAud.AllowsARM() {
		t.Fatal("issuer as aud")
	}
	if (authn.Principal{ID: "u"}).AllowsGraph() || (authn.Principal{ID: "u"}).AllowsARM() {
		t.Fatal("empty aud")
	}
	if !(authn.Principal{ID: "root", IsRoot: true}).AllowsGraph() || !(authn.Principal{ID: "root", IsRoot: true}).AllowsARM() {
		t.Fatal("root")
	}

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tok, err := authn.EncodeRS256JWT(key, "kid1", map[string]any{
		"aud": authn.AudienceARM,
		"iss": "http://127.0.0.1:4599/tid/v2.0",
		"oid": "user1",
		"exp": float64(now.Add(time.Hour).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &authn.Authenticator{Tokens: tokenStore{id: "user1", ok: true}}
	p, err := a.AuthenticateToken(tok)
	if err != nil || p.ID != "user1" {
		t.Fatalf("%+v %v", p, err)
	}
	if !p.AllowsARM() || p.AllowsGraph() {
		t.Fatalf("hash lookup skipped aud: %+v", p)
	}
	if _, err := a.AuthenticateToken("not.a.jwt"); err != authn.ErrUnauthenticated {
		t.Fatalf("unparseable jwt on hash hit: %v", err)
	}
}
