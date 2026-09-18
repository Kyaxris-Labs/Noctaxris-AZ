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
	h := &monitor.Handler{
		Store:          s.store,
		Authz:          s.authz,
		Now:            s.effectiveNow,
		ActivityInject: s.cfg.ActivityInject,
		LogsInject:     s.cfg.LogsInject,
		DefenderInject: s.cfg.DefenderInject,
		SubscriptionID: s.cfg.SubscriptionID,
		TenantID:       s.cfg.TenantID,
	}
	h.Mount(s.mux, principal)
}
