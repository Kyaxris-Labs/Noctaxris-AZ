package compute

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
)

// NewEngineClient builds a Docker API client for the nested DinD engine URL.
// Empty dockerHost returns (nil, nil): nested compute disabled.
func NewEngineClient(dockerHost, certPath string) (*client.Client, error) {
	host := strings.TrimSpace(dockerHost)
	if host == "" {
		return nil, nil
	}
	if err := ValidateDockerHost(host, certPath); err != nil {
		return nil, err
	}
	opts := []client.Opt{
		client.WithHost(host),
		client.WithAPIVersionNegotiation(),
	}
	certDir := strings.TrimSpace(certPath)
	if certDir != "" {
		opts = append(opts, client.WithTLSClientConfig(
			filepath.Join(certDir, "ca.pem"),
			filepath.Join(certDir, "cert.pem"),
			filepath.Join(certDir, "key.pem"),
		))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("compute: docker client: %w", err)
	}
	return cli, nil
}
