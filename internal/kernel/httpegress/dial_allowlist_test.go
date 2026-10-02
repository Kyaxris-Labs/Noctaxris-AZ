package httpegress_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/httpegress"
)

func TestPinnedDialRejectsPrivateAndMetadataAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, addr := range []string{
		"10.0.0.1:443",
		"192.168.1.1:80",
		"172.16.0.5:443",
		"169.254.169.254:80",
		"[::1]:80",
		"0.0.0.0:80",
	} {
		_, err := httpegress.PinnedDialContext(ctx, "tcp", addr)
		if err == nil {
			t.Fatalf("expected deny for %s", addr)
		}
	}

	// Public literal should leave the private/metadata filter and attempt dial.
	_, err := httpegress.PinnedDialContext(ctx, "tcp", "8.8.8.8:1")
	if err == nil {
		t.Fatal("expected dial failure on closed port")
	}

	c := httpegress.Client(250 * time.Millisecond)
	if c.Timeout != 250*time.Millisecond {
		t.Fatalf("timeout=%v", c.Timeout)
	}
}

func TestAllowedMetadataHostsAndBareLoopback(t *testing.T) {
	t.Setenv(httpegress.EnvHTTPEgress, "1")

	t.Setenv(httpegress.EnvHTTPAllowlist, "http://metadata.google.internal/")
	if err := httpegress.Allowed("http://metadata.google.internal/"); err == nil {
		t.Fatal("google metadata host must deny")
	}

	t.Setenv(httpegress.EnvHTTPAllowlist, "http://127.0.0.1/")
	if err := httpegress.Allowed("http://127.0.0.1/"); err == nil {
		t.Fatal("bare loopback without port must deny")
	}

	if err := httpegress.Allowed("http://127.0.0.1:8080/hook"); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := httpegress.PinnedDialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
