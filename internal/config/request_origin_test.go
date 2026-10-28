package config

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestCANameEnvOverridesStrip(t *testing.T) {
	t.Setenv("NOCTAXRIS_AZ_STRIP_PRODUCT", "1")
	t.Setenv("NOCTAXRIS_AZ_CA_CN", "Route Board")
	t.Setenv("NOCTAXRIS_AZ_CA_ORG", "Route Board")
	if got := LabCACommonName(); got != "Route Board" {
		t.Fatalf("cn=%q", got)
	}
	if got := LabCAOrganization(); got != "Route Board" {
		t.Fatalf("org=%q", got)
	}
}

func TestRequestOriginFollowsHostUnlessPinned(t *testing.T) {
	cfg := Config{ListenAddr: "0.0.0.0:4599"}
	req := httptestRequest("203.0.113.10:59991", false)
	if got := cfg.RequestOrigin(req); got != "http://203.0.113.10:59991" {
		t.Fatalf("origin=%q", got)
	}
	req.TLS = &tls.ConnectionState{}
	if got := cfg.RequestOrigin(req); got != "https://203.0.113.10:59991" {
		t.Fatalf("tls origin=%q", got)
	}
	req.Host = ""
	req.TLS = nil
	if got := cfg.RequestOrigin(req); got != "http://127.0.0.1:4599" {
		t.Fatalf("empty host origin=%q", got)
	}

	cfg.PublicURL = "https://lab.example:8443/"
	req.Host = "203.0.113.10:59991"
	if got := cfg.RequestOrigin(req); got != "https://lab.example:8443" {
		t.Fatalf("public url origin=%q", got)
	}

	cfg = Config{CloudHosts: true, ListenAddr: "127.0.0.1:4599"}
	req.Host = "203.0.113.10:59991"
	if got := cfg.RequestOrigin(req); got != "https://login.microsoftonline.com" {
		t.Fatalf("cloud hosts origin=%q", got)
	}
}

func TestRewriteLoopbackOrigin(t *testing.T) {
	raw := "http://127.0.0.1:4599/appconfig/cfg1"
	req := httptestRequest("203.0.113.10:59991", false)
	if got := RewriteLoopbackOrigin(raw, req); got != "http://203.0.113.10:59991/appconfig/cfg1" {
		t.Fatalf("rewrite=%q", got)
	}
	req.TLS = &tls.ConnectionState{}
	if got := RewriteLoopbackOrigin(raw, req); got != "https://203.0.113.10:59991/appconfig/cfg1" {
		t.Fatalf("tls rewrite=%q", got)
	}
	req.Host = ""
	req.TLS = nil
	if got := RewriteLoopbackOrigin(raw, req); got != raw {
		t.Fatalf("empty host rewrite=%q", got)
	}
	other := "https://config.example/appconfig/cfg1"
	req.Host = "203.0.113.10:59991"
	if got := RewriteLoopbackOrigin(other, req); got != other {
		t.Fatalf("non-loopback rewrite=%q", got)
	}
}

func TestLabOIDCIssuersMatchByPath(t *testing.T) {
	loop := "http://127.0.0.1:4599/_lab/oidc-lab"
	pub := "https://203.0.113.10:59991/_lab/oidc-lab"
	if !LabOIDCIssuersMatch(loop, pub) || !LabOIDCIssuersMatch(pub, loop) {
		t.Fatal("same lab path should match across hosts")
	}
	if !LabOIDCIssuersMatch(loop+"/", pub) {
		t.Fatal("trailing slash should still be the lab path")
	}
	product := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	if LabOIDCIssuersMatch(loop, product) {
		t.Fatal("different lab paths must not match")
	}
	if LabOIDCIssuersMatch(loop, "http://203.0.113.10:59991/_lab/oidc-lab/extra") {
		t.Fatal("longer path must not match")
	}
	if LabOIDCIssuersMatch(loop, "http://203.0.113.10:59991/_lab/oidc-laboratory") {
		t.Fatal("prefix lookalike must not match")
	}
	gh := "https://token.actions.githubusercontent.com"
	if LabOIDCIssuersMatch(loop, gh) || LabOIDCIssuersMatch(gh, pub) {
		t.Fatal("unrelated issuer must not match a lab path")
	}
	if !LabOIDCIssuersMatch(gh, gh) {
		t.Fatal("equal unrelated issuers should match")
	}
}

func httptestRequest(host string, tlsOn bool) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		panic(err)
	}
	req.Host = host
	if tlsOn {
		req.TLS = &tls.ConnectionState{}
	}
	return req
}
