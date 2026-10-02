package httpegress_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/httpegress"
)

func TestClientRejectsRedirectAndPinnedDialPrivate(t *testing.T) {
	c := httpegress.Client(0)
	if c.Timeout != 5*time.Second {
		t.Fatalf("timeout=%v", c.Timeout)
	}
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirects must be denied")
	}

	_, err := httpegress.PinnedDialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("loopback dial must fail")
	}
	_, err = httpegress.PinnedDialContext(context.Background(), "tcp", "not-a-host")
	if err == nil {
		t.Fatal("bad dial addr must fail")
	}

	t.Setenv(httpegress.EnvHTTPEgress, "true")
	t.Setenv(httpegress.EnvHTTPAllowlist, "https://example.com/hook")
	if err := httpegress.Allowed("https://example.com/hook"); err != nil {
		t.Fatal(err)
	}
	if err := httpegress.Allowed("http://metadata.azure.com/"); err == nil {
		t.Fatal("azure metadata host must deny")
	}
	if err := httpegress.Allowed("http://metadata/"); err == nil {
		t.Fatal("metadata short name must deny")
	}

	// Exercise Client construction path used by delivery callers.
	_ = httpegress.Client(time.Millisecond)
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	_, _ = c.Do(req)
}
