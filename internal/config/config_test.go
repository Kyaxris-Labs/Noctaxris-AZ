package config

import "testing"

func TestListenIsLoopback(t *testing.T) {
	if !ListenIsLoopback("127.0.0.1:4599") {
		t.Fatal("expected loopback")
	}
	if ListenIsLoopback("0.0.0.0:4599") {
		t.Fatal("expected non-loopback")
	}
	if err := ValidateCloudHostsListen(Config{CloudHosts: true, CloudHostsListen: "0.0.0.0:443"}); err == nil {
		t.Fatal("expected cloud hosts error")
	}
}

func TestExampleRootCredentials(t *testing.T) {
	if !ExampleRootCredentials(exampleRootClientID, exampleRootAccessToken) {
		t.Fatal("expected example pair")
	}
	if ExampleRootCredentials("other", "token") {
		t.Fatal("unexpected match")
	}
}

func TestValidateListenSecurity(t *testing.T) {
	err := ValidateListenSecurity(Config{ListenAddr: "0.0.0.0:4599"})
	if err == nil {
		t.Fatal("expected error")
	}
	err = ValidateListenSecurity(Config{ListenAddr: "0.0.0.0:4599", AllowNonLoopbackListen: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicBaseRewritesWildcardListen(t *testing.T) {
	cfg := Config{ListenAddr: "0.0.0.0:4599"}
	if got := cfg.PublicBase(); got != "http://127.0.0.1:4599" {
		t.Fatalf("PublicBase=%q", got)
	}
	cfg.TLSAuto = true
	if got := cfg.PublicBase(); got != "https://127.0.0.1:4599" {
		t.Fatalf("TLS PublicBase=%q", got)
	}
	cfg.PublicURL = "https://lab.example:8443/"
	if got := cfg.IssuerBase(); got != "https://lab.example:8443" {
		t.Fatalf("IssuerBase=%q", got)
	}
	if got := cfg.ResourceManagerBase(); got != "https://lab.example:8443" {
		t.Fatalf("ResourceManagerBase=%q", got)
	}
	if cfg.CAPath() != "/_noctaxris-az/ca.pem" {
		t.Fatalf("CAPath=%q", cfg.CAPath())
	}
}
