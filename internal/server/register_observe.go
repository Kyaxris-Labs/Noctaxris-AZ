package server

import (
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
)

func (s *Server) registerObserve() {
	principal := func(r *http.Request) (authn.Principal, bool) {
		return PrincipalFromContext(r.Context())
	}
	(&monitor.Handler{Store: s.store, Authz: s.authz}).Mount(s.mux, principal)
}
