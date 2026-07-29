package config

import "testing"

func TestListenIsLoopback(t *testing.T) {
	if !ListenIsLoopback("127.0.0.1:4599") {
		t.Fatal("expected loopback")
	}
	if ListenIsLoopback("0.0.0.0:4599") {
		t.Fatal("expected non-loopback")
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
