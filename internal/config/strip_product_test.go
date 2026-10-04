package config

import "testing"

func TestStripProductHelpersDefaultAndOn(t *testing.T) {
	t.Setenv(EnvStripProduct, "")
	if StripProductEnabled() {
		t.Fatal("default off")
	}
	if OpsPathPrefix() != productOpsPathPrefix || ReadyPath() != productOpsPathPrefix+"/ready" {
		t.Fatalf("default ops paths: %s %s", OpsPathPrefix(), ReadyPath())
	}
	if LabDisplayName() != productLabDisplay {
		t.Fatalf("display %q", LabDisplayName())
	}
	if LabCACommonName() != productLabCACN || LabCAOrganization() != productLabCAOrg {
		t.Fatalf("ca %q / %q", LabCACommonName(), LabCAOrganization())
	}
	cfg := Config{}
	if cfg.OpsPathPrefix() != productOpsPathPrefix || cfg.LabDisplayName() != productLabDisplay {
		t.Fatalf("cfg default %+v", cfg)
	}

	t.Setenv(EnvStripProduct, "1")
	if !StripProductEnabled() {
		t.Fatal("strip on")
	}
	if OpsPathPrefix() != labOpsPathPrefix || ReadyPath() != labOpsPathPrefix+"/ready" {
		t.Fatalf("strip ops paths: %s %s", OpsPathPrefix(), ReadyPath())
	}
	if LabDisplayName() != stripLabDisplay {
		t.Fatalf("strip display %q", LabDisplayName())
	}
	if LabCACommonName() != stripLabCACN || LabCAOrganization() != stripLabCAOrg {
		t.Fatalf("strip ca %q / %q", LabCACommonName(), LabCAOrganization())
	}
	cfg.StripProduct = true
	if cfg.HealthPath() != labOpsPathPrefix+"/health" ||
		cfg.ReadyPath() != labOpsPathPrefix+"/ready" ||
		cfg.VersionPath() != labOpsPathPrefix+"/version" ||
		cfg.LabDisplayName() != stripLabDisplay {
		t.Fatalf("cfg strip %+v paths %s %s %s", cfg, cfg.HealthPath(), cfg.ReadyPath(), cfg.VersionPath())
	}

	t.Setenv(EnvStripProduct, "true")
	if !StripProductEnabled() {
		t.Fatal("true should enable")
	}
	t.Setenv(EnvStripProduct, "")
}

func TestLoadFromEnvStripProduct(t *testing.T) {
	t.Setenv("NOCTAXRIS_AZ_LISTEN", "127.0.0.1:4599")
	t.Setenv("NOCTAXRIS_AZ_AMQP_LISTEN", "127.0.0.1:5672")
	t.Setenv("NOCTAXRIS_AZ_DATA_ROOT", t.TempDir())
	t.Setenv("NOCTAXRIS_AZ_ROOT_CLIENT_ID", "cid")
	t.Setenv("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN", "tok")
	t.Setenv("NOCTAXRIS_AZ_DOCKER_HOST", "")
	t.Setenv(EnvStripProduct, "")
	cfg, err := LoadFromEnv()
	if err != nil || cfg.StripProduct {
		t.Fatalf("default strip: %+v %v", cfg, err)
	}
	t.Setenv(EnvStripProduct, "1")
	cfg, err = LoadFromEnv()
	if err != nil || !cfg.StripProduct {
		t.Fatalf("strip on: %+v %v", cfg, err)
	}
}
