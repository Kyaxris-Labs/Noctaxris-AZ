package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromEnvAndTLSAMQP(t *testing.T) {
	t.Setenv("NOCTAXRIS_AZ_LISTEN", "127.0.0.1:4599")
	t.Setenv("NOCTAXRIS_AZ_AMQP_LISTEN", "127.0.0.1:5672")
	t.Setenv("NOCTAXRIS_AZ_DATA_ROOT", t.TempDir())
	t.Setenv("NOCTAXRIS_AZ_ROOT_CLIENT_ID", "cid")
	t.Setenv("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN", "tok")
	t.Setenv("NOCTAXRIS_AZ_DOCKER_HOST", "")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootClientID != "cid" || cfg.RootAccessToken != "tok" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.TLSEnabled() {
		t.Fatal("tls off")
	}
	cfg.TLSCertFile = "a"
	cfg.TLSKeyFile = "b"
	if !cfg.TLSEnabled() {
		t.Fatal("tls on")
	}

	if err := ValidateAMQPListenSecurity(Config{AMQPListenAddr: "0.0.0.0:5672"}); err == nil {
		t.Fatal("amqp non-loopback")
	}
	if err := ValidateAMQPListenSecurity(Config{AMQPListenAddr: "0.0.0.0:5672", AllowNonLoopbackListen: true}); err != nil {
		t.Fatal(err)
	}
	if !ListenIsLoopback("localhost:1") || !ListenIsLoopback("[::1]:1") {
		t.Fatal("loopback hosts")
	}
	if ListenIsLoopback("") || ListenIsLoopback(":4599") {
		t.Fatal("empty/:")
	}
	if !AzuriteWellKnownCredentials(azuriteAccountName, azuriteAccountKey) {
		t.Fatal("azurite")
	}

	t.Setenv(EnvCloudHosts, "1")
	t.Setenv("NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN", "0.0.0.0:443")
	t.Setenv(EnvAllowNonLoopbackListen, "")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected cloud hosts listen fail")
	}
	t.Setenv("NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN", "127.0.0.1:8443")
	cfg, err = LoadFromEnv()
	if err != nil || !cfg.CloudHosts || cfg.IssuerBase() != "https://login.microsoftonline.com" {
		t.Fatalf("%+v %v", cfg, err)
	}

	t.Setenv("NOCTAXRIS_AZ_LISTEN", "0.0.0.0:4599")
	t.Setenv(EnvAllowNonLoopbackListen, "")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected listen fail")
	}
	t.Setenv(EnvAllowNonLoopbackListen, "1")
	t.Setenv("NOCTAXRIS_AZ_AMQP_LISTEN", "0.0.0.0:5672")
	if _, err := LoadFromEnv(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("NOCTAXRIS_AZ_LISTEN", "127.0.0.1:4599")
	t.Setenv("NOCTAXRIS_AZ_AMQP_LISTEN", "127.0.0.1:5672")
	t.Setenv("NOCTAXRIS_AZ_DOCKER_HOST", "tcp://noctaxris-az-engine:2376")
	t.Setenv("NOCTAXRIS_AZ_DOCKER_CERT_PATH", dir)
	if _, err := LoadFromEnv(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NOCTAXRIS_AZ_LISTEN", "127.0.0.1:4599")
	t.Setenv("NOCTAXRIS_AZ_AMQP_LISTEN", "127.0.0.1:5672")
	t.Setenv(EnvAllowNonLoopbackListen, "")
	t.Setenv(EnvLabForensics, "")
	t.Setenv(EnvActivityInject, "")
	t.Setenv(EnvLogsInject, "")
	t.Setenv(EnvDefenderInject, "")
	cfg, err = LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LabForensics || cfg.ActivityInject || cfg.LogsInject || cfg.DefenderInject {
		t.Fatalf("forensics flags should default off: %+v", cfg)
	}
	t.Setenv(EnvLabForensics, "1")
	t.Setenv(EnvActivityInject, "true")
	t.Setenv(EnvLogsInject, "1")
	t.Setenv(EnvDefenderInject, "true")
	cfg, err = LoadFromEnv()
	if err != nil || !cfg.LabForensics || !cfg.ActivityInject || !cfg.LogsInject || !cfg.DefenderInject {
		t.Fatalf("forensics flags on: %+v %v", cfg, err)
	}
}
