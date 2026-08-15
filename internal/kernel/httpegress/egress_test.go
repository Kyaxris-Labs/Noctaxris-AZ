package httpegress_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/httpegress"
)

func TestAllowedLabLocalAndDeny(t *testing.T) {
	if err := httpegress.Allowed("http://127.0.0.1:4599/hook"); err != nil {
		t.Fatal(err)
	}
	if err := httpegress.Allowed("http://localhost:4599/x"); err != nil {
		t.Fatal(err)
	}
	if err := httpegress.Allowed("ftp://example.com/x"); err == nil {
		t.Fatal("scheme")
	}
	if err := httpegress.Allowed("://bad"); err == nil {
		t.Fatal("invalid")
	}
	if err := httpegress.Allowed("https://example.com/x"); err == nil {
		t.Fatal("egress off")
	}

	t.Setenv(httpegress.EnvHTTPEgress, "1")
	t.Setenv(httpegress.EnvHTTPAllowlist, "https://example.com/x")
	if err := httpegress.Allowed("https://example.com/x"); err != nil {
		t.Fatal(err)
	}
	if err := httpegress.Allowed("https://other.com/x"); err == nil {
		t.Fatal("not allowlisted")
	}
	if err := httpegress.Allowed("http://169.254.169.254/"); err == nil {
		t.Fatal("metadata")
	}
	t.Setenv(httpegress.EnvHTTPAllowlist, "http://10.0.0.1/")
	if err := httpegress.Allowed("http://10.0.0.1/"); err == nil {
		t.Fatal("private")
	}
}
