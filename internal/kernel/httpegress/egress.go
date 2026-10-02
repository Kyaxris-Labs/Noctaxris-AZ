package httpegress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	EnvHTTPEgress    = "NOCTAXRIS_AZ_HTTP_EGRESS"
	EnvHTTPAllowlist = "NOCTAXRIS_AZ_HTTP_ALLOWLIST"
)

// Allowed reports whether destURL may be fetched for lab push/webhook delivery.
func Allowed(destURL string) error {
	u, err := url.Parse(destURL)
	if err != nil {
		return fmt.Errorf("egress: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("egress: scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if isLabLocal(u) {
		return nil
	}
	if !egressEnabled() {
		return fmt.Errorf("egress: denied (set %s=1 and allowlist)", EnvHTTPEgress)
	}
	if !exactAllowlisted(destURL) {
		return fmt.Errorf("egress: url not in %s", EnvHTTPAllowlist)
	}
	if isPrivateOrMetadataHost(host) {
		return fmt.Errorf("egress: private/metadata host denied")
	}
	return nil
}

// Client returns an HTTP client that denies redirects and pins dial to non-private IPs.
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = PinnedDialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("egress: redirects are not allowed")
		},
	}
}

// PinnedDialContext resolves addr, rejects unsafe IPs at dial time, and connects to a validated address.
func PinnedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress: dial addr: %w", err)
	}
	var dialer net.Dialer
	// Lab-local emulator/httptest endpoints bind on loopback with an explicit port.
	if host == "127.0.0.1" || host == "localhost" {
		return dialer.DialContext(ctx, network, addr)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			return nil, fmt.Errorf("egress: resolve dial host: %w", err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("egress: no addresses for %s", host)
	}
	var last error
	for _, ip := range ips {
		if ipUnsafe(ip) {
			last = fmt.Errorf("egress: private/metadata address denied")
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("egress: private/metadata address denied")
	}
	return nil, last
}

func egressEnabled() bool {
	v := os.Getenv(EnvHTTPEgress)
	return v == "1" || strings.EqualFold(v, "true")
}

func exactAllowlisted(dest string) bool {
	raw := strings.TrimSpace(os.Getenv(EnvHTTPAllowlist))
	for _, p := range strings.Split(raw, ",") {
		if strings.TrimSpace(p) == dest {
			return true
		}
	}
	return false
}

func isLabLocal(u *url.URL) bool {
	host := u.Hostname()
	port := u.Port()
	// Explicit-port loopback only (httptest and API :4599). Bare localhost/127.0.0.1 without a port stays gated.
	if port == "" {
		return false
	}
	return host == "127.0.0.1" || host == "localhost"
}

func isPrivateOrMetadataHost(host string) bool {
	if strings.EqualFold(host, "metadata.google.internal") ||
		strings.EqualFold(host, "169.254.169.254") ||
		strings.EqualFold(host, "metadata") ||
		strings.EqualFold(host, "metadata.azure.com") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ipUnsafe(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// Unresolvable names are not treated as private here; PinnedDialContext enforces at dial time.
		return false
	}
	for _, ip := range ips {
		if ipUnsafe(ip) {
			return true
		}
	}
	return false
}

func ipUnsafe(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
