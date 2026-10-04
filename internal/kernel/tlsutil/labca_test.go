package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func TestDefaultCloudHostSANsIncludeAzureCloud(t *testing.T) {
	sans := DefaultCloudHostSANs()
	want := map[string]bool{
		"login.microsoftonline.com": true,
		"graph.microsoft.com":       true,
		"management.azure.com":      true,
		"graph.windows.net":         true,
	}
	for _, s := range sans {
		delete(want, s)
	}
	if len(want) > 0 {
		t.Fatalf("missing SANs: %v", want)
	}
	if !AllowedCloudHost("graph.microsoft.com") || !AllowedCloudHost("127.0.0.1:443") {
		t.Fatal("allowed host")
	}
	if AllowedCloudHost("evil.example") {
		t.Fatal("unexpected host")
	}
}

func TestEnsureServerCertWritesSANCert(t *testing.T) {
	t.Setenv("NOCTAXRIS_AZ_STRIP_PRODUCT", "")
	dir := t.TempDir()
	p, err := EnsureServerCert(dir, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p.ServerCert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range cert.DNSNames {
		if n == "login.microsoftonline.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dns names: %v", cert.DNSNames)
	}
	caRaw, err := os.ReadFile(p.CACert)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caRaw)
	if caBlock == nil {
		t.Fatal("ca pem")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if caCert.Subject.CommonName != "Noctaxris-AZ Lab CA" {
		t.Fatalf("ca cn %q", caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Organization) != 1 || caCert.Subject.Organization[0] != "Noctaxris-AZ" {
		t.Fatalf("ca org %#v", caCert.Subject.Organization)
	}
	if _, err := LoadTLSConfig(p); err != nil {
		t.Fatal(err)
	}
	p2, err := EnsureServerCert(dir, time.Time{})
	if err != nil || p2.ServerCert != p.ServerCert {
		t.Fatal(err)
	}
}

func TestEnsureServerCertStripProductCA(t *testing.T) {
	t.Setenv("NOCTAXRIS_AZ_STRIP_PRODUCT", "1")
	dir := t.TempDir()
	p, err := EnsureServerCert(dir, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	caRaw, err := os.ReadFile(p.CACert)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caRaw)
	if caBlock == nil {
		t.Fatal("ca pem")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if caCert.Subject.CommonName != "Lab CA" {
		t.Fatalf("strip ca cn %q", caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Organization) != 1 || caCert.Subject.Organization[0] != "Lab" {
		t.Fatalf("strip ca org %#v", caCert.Subject.Organization)
	}
}
