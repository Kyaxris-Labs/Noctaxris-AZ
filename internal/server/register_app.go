package server

import (
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appconfig"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/functions"
)

func (s *Server) registerApp() {
	principal := func(r *http.Request) (authn.Principal, bool) {
		return PrincipalFromContext(r.Context())
	}
	appCfg := &appconfig.Handler{Store: s.store, Authz: s.authz}
	if strings.TrimSpace(s.cfg.PublicURL) != "" {
		appCfg.PublicBase = s.cfg.PublicBase()
	}
	appCfg.Mount(s.mux, principal)
	(&functions.Handler{Store: s.store, Authz: s.authz}).Mount(s.mux, principal)
}
