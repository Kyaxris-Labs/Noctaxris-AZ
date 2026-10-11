package entra

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

// handleInstanceDiscovery serves MSAL / Azure CLI AAD instance discovery.
// GET /{tenant}/discovery/instance?api-version=1.1&authorization_endpoint=...
func (s *Service) handleInstanceDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		azerrors.BadRequest(w, "method not allowed")
		return
	}
	base := s.base()
	tenant := s.pathTenant(r)
	authEndpoint := strings.TrimSpace(r.URL.Query().Get("authorization_endpoint"))
	if authEndpoint == "" {
		authEndpoint = base + "/" + tenant + "/oauth2/v2.0/authorize"
	}
	_ = authEndpoint
	networkHost := hostFromBase(base)
	tenantDiscovery := base + "/" + tenant + "/v2.0/.well-known/openid-configuration"
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_discovery_endpoint": tenantDiscovery,
		"api-version":               "1.1",
		"metadata": []map[string]any{{
			"preferred_network": networkHost,
			"preferred_cache":   networkHost,
			"aliases":           []string{networkHost},
		}},
	})
}

func hostFromBase(base string) string {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" {
		return "127.0.0.1:4599"
	}
	return u.Host
}
