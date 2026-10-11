// Package hostroute rewrites AzureCloud Host-style URLs onto lab path prefixes.
package hostroute

import (
	"net"
	"net/http"
	"path"
	"strings"
)

// RewritePath maps Host-virtual Azure endpoints onto Noctaxris-AZ path prefixes.
// Path-style Hosts (loopback, empty) are unchanged so challenge curl flows stay intact.
// When an AzureCloud Host is present, the Host label always wins over a conflicting
// lab path prefix (no cross-account / cross-vault Host spoof).
func RewritePath(host, rawPath string) string {
	h := hostname(host)
	if h == "" || isLoopbackHost(h) {
		return rawPath
	}
	p, ok := cleanPath(rawPath)
	if !ok {
		return rawPath
	}

	switch {
	case strings.HasSuffix(h, ".vault.azure.net"):
		vault := strings.TrimSuffix(h, ".vault.azure.net")
		if !validLabel(vault) {
			return rawPath
		}
		return joinPrefix("/keyvault/"+vault, stripLabPrefix(p, "/keyvault/"))
	case strings.HasSuffix(h, ".blob.core.windows.net"):
		account := strings.TrimSuffix(h, ".blob.core.windows.net")
		if !validLabel(account) {
			return rawPath
		}
		return joinPrefix("/blob/"+account, stripLabPrefix(p, "/blob/"))
	case strings.HasSuffix(h, ".queue.core.windows.net"):
		account := strings.TrimSuffix(h, ".queue.core.windows.net")
		if !validLabel(account) {
			return rawPath
		}
		return joinPrefix("/queue/"+account, stripLabPrefix(p, "/queue/"))
	case strings.HasSuffix(h, ".table.core.windows.net"):
		account := strings.TrimSuffix(h, ".table.core.windows.net")
		if !validLabel(account) {
			return rawPath
		}
		return joinPrefix("/table/"+account, stripLabPrefix(p, "/table/"))
	case strings.HasSuffix(h, ".azconfig.io"):
		store := strings.TrimSuffix(h, ".azconfig.io")
		if !validLabel(store) {
			return rawPath
		}
		return joinPrefix("/appconfig/"+store, stripLabPrefix(p, "/appconfig/"))
	default:
		return rawPath
	}
}

// Apply rewrites r.URL.Path from the request Host when needed.
// Authn/authz still run on the rewritten path (Shared Key / SAS / Bearer + RBAC).
func Apply(r *http.Request) {
	if r == nil || r.URL == nil {
		return
	}
	next := RewritePath(r.Host, r.URL.Path)
	if next == r.URL.Path {
		return
	}
	u := *r.URL
	u.Path = next
	u.RawPath = ""
	r.URL = &u
}

func hostname(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

func isLoopbackHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "[::]":
		return true
	default:
		return false
	}
}

func cleanPath(raw string) (string, bool) {
	p := normalizePath(raw)
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		return raw, false
	}
	// path.Clean already collapses ".."; reject oddities that remain.
	if strings.Contains(cleaned, "..") {
		return raw, false
	}
	return cleaned, true
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func validLabel(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "/") || strings.Contains(s, "..") {
		return false
	}
	return true
}

// stripLabPrefix removes /{prefix}{name}/... account/vault segment when present.
func stripLabPrefix(p, prefix string) string {
	if !strings.HasPrefix(p, prefix) {
		return p
	}
	rest := strings.TrimPrefix(p, prefix)
	if rest == "" {
		return "/"
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return "/"
}

func joinPrefix(prefix, p string) string {
	if p == "" || p == "/" {
		return prefix
	}
	if !strings.HasPrefix(p, "/") {
		return prefix + "/" + p
	}
	return prefix + p
}
