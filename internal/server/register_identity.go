package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/authorization"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func (s *Server) registerIdentity() {
	(&entra.Service{
		Store:    s.store,
		TenantID: s.cfg.TenantID,
	}).Mount(s.mux)

	(&subscriptions.Service{
		Store:          s.store,
		Authz:          s.authz,
		SubscriptionID: s.cfg.SubscriptionID,
		PrincipalFrom:  PrincipalFromContext,
	}).Mount(s.mux)

	(&authorization.Service{
		Store:          s.store,
		Authz:          s.authz,
		SubscriptionID: s.cfg.SubscriptionID,
		PrincipalFrom:  PrincipalFromContext,
	}).Mount(s.mux)
}
