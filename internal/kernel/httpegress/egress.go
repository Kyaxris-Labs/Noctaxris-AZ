package httpegress

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
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
	if isPrivateOrMetadata(host) {
		return fmt.Errorf("egress: private/metadata host denied")
	}
	return nil
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
	if port == "" {
		return false
	}
	if (host == "127.0.0.1" || host == "localhost") && port == "4599" {
		return true
	}
	return false
}

func isPrivateOrMetadata(host string) bool {
	if strings.EqualFold(host, "metadata.google.internal") ||
		strings.EqualFold(host, "169.254.169.254") ||
		strings.EqualFold(host, "metadata") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
