package compute

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	EnvDockerHostAllowlist = "NOCTAXRIS_AZ_DOCKER_HOST_ALLOWLIST"
	defaultDockerHost      = "tcp://noctaxris-az-engine:2376"
)

// ValidateDockerHost rejects host-engine schemes and non-allowlisted endpoints.
func ValidateDockerHost(dockerHost, tlsCertPath string) error {
	host := strings.TrimSpace(dockerHost)
	if host == "" {
		return nil
	}
	lower := strings.ToLower(host)
	if strings.Contains(lower, "docker.sock") {
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST must not reference docker.sock")
	}
	u, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "unix", "npipe":
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST scheme %q is not allowed (use tcp:// to noctaxris-az-engine)", scheme)
	case "tcp":
	default:
		if scheme == "" {
			return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST must be a tcp:// URL")
		}
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST scheme %q is not allowed", scheme)
	}
	if !dockerHostAllowlisted(host) {
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_HOST %q is not allowlisted (default %s; extend via %s)",
			host, defaultDockerHost, EnvDockerHostAllowlist)
	}
	certDir := strings.TrimSpace(tlsCertPath)
	if certDir == "" {
		return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_CERT_PATH is required when NOCTAXRIS_AZ_DOCKER_HOST is set")
	}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		p := filepath.Join(certDir, name)
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_CERT_PATH: %s: %w", name, err)
		}
		if st.IsDir() || st.Size() == 0 {
			return fmt.Errorf("compute: NOCTAXRIS_AZ_DOCKER_CERT_PATH: %s must be a non-empty file", name)
		}
	}
	return nil
}

func dockerHostAllowlisted(host string) bool {
	want := strings.TrimRight(strings.TrimSpace(host), "/")
	for _, entry := range dockerHostAllowlist() {
		if strings.EqualFold(entry, want) {
			return true
		}
	}
	return false
}

func dockerHostAllowlist() []string {
	out := []string{defaultDockerHost}
	raw := strings.TrimSpace(os.Getenv(EnvDockerHostAllowlist))
	if raw == "" {
		return out
	}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
