package server

import (
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appconfig"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/functions"
)

func (s *Server) registerApp() {
	principal := func(r *http.Request) (authn.Principal, bool) {
		return PrincipalFromContext(r.Context())
	}
	(&appconfig.Handler{Store: s.store, Authz: s.authz}).Mount(s.mux, principal)
	(&functions.Handler{Store: s.store, Authz: s.authz}).Mount(s.mux, principal)
}
