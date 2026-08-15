package compute_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/compute"
)

func TestValidateDockerHost(t *testing.T) {
	if err := compute.ValidateDockerHost("", ""); err != nil {
		t.Fatal(err)
	}
	if err := compute.ValidateDockerHost("unix:///var/run/docker.sock", ""); err == nil {
		t.Fatal("sock")
	}
	if err := compute.ValidateDockerHost("npipe:////./pipe/docker_engine", ""); err == nil {
		t.Fatal("npipe")
	}
	if err := compute.ValidateDockerHost("tcp://evil:2376", ""); err == nil {
		t.Fatal("not allowlisted")
	}
	dir := t.TempDir()
	if err := compute.ValidateDockerHost("tcp://noctaxris-az-engine:2376", dir); err == nil {
		t.Fatal("missing certs")
	}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := compute.ValidateDockerHost("tcp://noctaxris-az-engine:2376", dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv(compute.EnvDockerHostAllowlist, "tcp://custom:2376")
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		_ = os.WriteFile(filepath.Join(dir, name), []byte("pem"), 0o600)
	}
	if err := compute.ValidateDockerHost("tcp://custom:2376", dir); err != nil {
		t.Fatal(err)
	}
}
