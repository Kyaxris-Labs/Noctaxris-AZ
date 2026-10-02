package compute_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/compute"
)

func TestNewEngineClientDisabledAndValidateFailures(t *testing.T) {
	cli, err := compute.NewEngineClient("", "")
	if err != nil || cli != nil {
		t.Fatalf("disabled engine: cli=%v err=%v", cli, err)
	}

	_, err = compute.NewEngineClient("tcp://noctaxris-az-engine:2376", "")
	if err == nil || !strings.Contains(err.Error(), "DOCKER_CERT_PATH") {
		t.Fatalf("missing cert path: %v", err)
	}

	_, err = compute.NewEngineClient("http://noctaxris-az-engine:2376", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("http scheme: %v", err)
	}

	_, err = compute.NewEngineClient("tcp://host/docker.sock", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "docker.sock") {
		t.Fatalf("docker.sock: %v", err)
	}

	_, err = compute.NewEngineClient("noctaxris-az-engine:2376", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("missing scheme: %v", err)
	}

	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := compute.ValidateDockerHost("tcp://noctaxris-az-engine:2376", dir); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(empty, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := compute.ValidateDockerHost("tcp://noctaxris-az-engine:2376", empty); err == nil {
		t.Fatal("empty cert files must fail")
	}

	// NewEngineClient TLS parse fails on placeholder PEM after ValidateDockerHost succeeds.
	_, err = compute.NewEngineClient("tcp://noctaxris-az-engine:2376", dir)
	if err == nil {
		t.Fatal("expected TLS client config failure for placeholder PEM")
	}
	if !strings.Contains(err.Error(), "docker client") {
		t.Fatalf("client err: %v", err)
	}
}

func TestAllowImagePullExactAllowlistWithoutDigestHost(t *testing.T) {
	t.Setenv(compute.EnvImagePullAllowlist, "localtool, ,ghcr.io/example/")
	if err := compute.AllowImagePull("localtool"); err != nil {
		t.Fatal(err)
	}
	if err := compute.AllowImagePull("other"); err == nil {
		t.Fatal("unknown exact ref must fail")
	}
	if err := compute.AllowImagePull("ghcr.io/example/app@sha256:" + strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
}
