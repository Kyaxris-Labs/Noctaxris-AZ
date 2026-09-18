package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/authorization"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/managedidentity"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func (s *Server) registerIdentity() {
	es := &entra.Service{
		Store:      s.store,
		TenantID:   s.cfg.TenantID,
		PublicBase: s.cfg.IssuerBase(),
		AuditNow:   s.effectiveNow,
	}
	s.authn.JWT = es
	es.Mount(s.mux)

	(&subscriptions.Service{
		Store:          s.store,
		Authz:          s.authz,
		SubscriptionID: s.cfg.SubscriptionID,
		TenantID:       s.cfg.TenantID,
		PrincipalFrom:  PrincipalFromContext,
		Now:            s.effectiveNow,
	}).Mount(s.mux)

	(&authorization.Service{
		Store:          s.store,
		Authz:          s.authz,
		SubscriptionID: s.cfg.SubscriptionID,
		PrincipalFrom:  PrincipalFromContext,
	}).Mount(s.mux)

	(&managedidentity.Handler{
		Store:    s.store,
		Auth:     s.authn,
		Authz:    s.authz,
		Entra:    es,
		TenantID: s.cfg.TenantID,
		AuditNow: s.effectiveNow,
	}).Register(s.mux)
}
