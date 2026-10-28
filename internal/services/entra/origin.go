package entra

import (
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
)

// origin is the advertised scheme and host for discovery and issuer URLs.
// FollowRequestHost uses the request Host (http unless r.TLS is set).
// An empty Host, or FollowRequestHost false, falls back to PublicBase.
func (s *Service) origin(r *http.Request) string {
	if s.FollowRequestHost {
		if o := config.OriginFromRequest(r); o != "" {
			return o
		}
	}
	return s.base()
}
