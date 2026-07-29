package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/compute"
)

const (
	EnvAllowNonLoopbackListen = "NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN"

	DefaultListenAddr     = "127.0.0.1:4599"
	DefaultAMQPListenAddr = "127.0.0.1:5672"
	DefaultDataRoot       = "/var/lib/noctaxris-az"
	// Fixed lab GUIDs (not secrets).
	DefaultTenantID       = "00000000-0000-0000-0000-000000000001"
	DefaultSubscriptionID = "00000000-0000-0000-0000-000000000002"
)

const (
	exampleRootClientID     = "00000000-0000-0000-0000-00000000root"
	exampleRootAccessToken  = "noctaxris-az-example-root-token"
	azuriteAccountName      = "devstoreaccount1"
	azuriteAccountKey       = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

// Config holds process configuration from NOCTAXRIS_AZ_* environment variables.
type Config struct {
	ListenAddr             string
	AMQPListenAddr         string
	DataRoot               string
	MasterKeyPath          string
	TLSCertFile            string
	TLSKeyFile             string
	RootClientID           string
	RootAccessToken        string
	TenantID               string
	SubscriptionID         string
	AllowNonLoopbackListen bool
	DockerHost             string
	DockerTLSCertPath      string
}

// LoadFromEnv reads configuration from the process environment.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:             getenv("NOCTAXRIS_AZ_LISTEN", DefaultListenAddr),
		AMQPListenAddr:         getenv("NOCTAXRIS_AZ_AMQP_LISTEN", DefaultAMQPListenAddr),
		DataRoot:               getenv("NOCTAXRIS_AZ_DATA_ROOT", DefaultDataRoot),
		MasterKeyPath:          getenv("NOCTAXRIS_AZ_MASTER_KEY_FILE", ""),
		TLSCertFile:            getenv("NOCTAXRIS_AZ_TLS_CERT", ""),
		TLSKeyFile:             getenv("NOCTAXRIS_AZ_TLS_KEY", ""),
		RootClientID:           getenv("NOCTAXRIS_AZ_ROOT_CLIENT_ID", ""),
		RootAccessToken:        getenv("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN", ""),
		TenantID:               getenv("NOCTAXRIS_AZ_TENANT_ID", DefaultTenantID),
		SubscriptionID:         getenv("NOCTAXRIS_AZ_SUBSCRIPTION_ID", DefaultSubscriptionID),
		AllowNonLoopbackListen: envTruthy(EnvAllowNonLoopbackListen),
		DockerHost:             getenv("NOCTAXRIS_AZ_DOCKER_HOST", ""),
		DockerTLSCertPath:      getenv("NOCTAXRIS_AZ_DOCKER_CERT_PATH", ""),
	}
	if err := compute.ValidateDockerHost(cfg.DockerHost, cfg.DockerTLSCertPath); err != nil {
		return Config{}, err
	}
	if err := ValidateListenSecurity(cfg); err != nil {
		return Config{}, err
	}
	if err := ValidateAMQPListenSecurity(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envTruthy(key string) bool {
	return strings.EqualFold(os.Getenv(key), "1") ||
		strings.EqualFold(os.Getenv(key), "true")
}

// ExampleRootCredentials reports whether id and token match docker/.env.example.
func ExampleRootCredentials(clientID, token string) bool {
	return clientID == exampleRootClientID && token == exampleRootAccessToken
}

// AzuriteWellKnownCredentials reports the classic Azurite account/key pair.
func AzuriteWellKnownCredentials(account, key string) bool {
	return account == azuriteAccountName && key == azuriteAccountKey
}

// ListenIsLoopback reports whether addr binds only loopback.
func ListenIsLoopback(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return false
		}
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// TLSEnabled reports whether both TLS PEM paths are set.
func (c Config) TLSEnabled() bool {
	return strings.TrimSpace(c.TLSCertFile) != "" && strings.TrimSpace(c.TLSKeyFile) != ""
}

// ValidateListenSecurity fails closed for non-loopback HTTP without TLS/allow.
func ValidateListenSecurity(c Config) error {
	if ListenIsLoopback(c.ListenAddr) {
		return nil
	}
	if c.TLSEnabled() {
		return nil
	}
	if c.AllowNonLoopbackListen || envTruthy(EnvAllowNonLoopbackListen) {
		return nil
	}
	return fmt.Errorf("NOCTAXRIS_AZ_LISTEN %q is non-loopback without TLS; set NOCTAXRIS_AZ_TLS_CERT and NOCTAXRIS_AZ_TLS_KEY, or %s=1 when host publish stays loopback (Compose)",
		c.ListenAddr, EnvAllowNonLoopbackListen)
}

// ValidateAMQPListenSecurity fails closed for non-loopback AMQP without allow.
func ValidateAMQPListenSecurity(c Config) error {
	if ListenIsLoopback(c.AMQPListenAddr) {
		return nil
	}
	if c.AllowNonLoopbackListen || envTruthy(EnvAllowNonLoopbackListen) {
		return nil
	}
	return fmt.Errorf("NOCTAXRIS_AZ_AMQP_LISTEN %q is non-loopback; set %s=1 when host publish stays loopback (Compose)",
		c.AMQPListenAddr, EnvAllowNonLoopbackListen)
}
