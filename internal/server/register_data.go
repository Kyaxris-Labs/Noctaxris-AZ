package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/servicebus"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
)

func (s *Server) registerData() {
	(&keyvault.Handler{
		Store: s.store,
		Auth:  s.authn,
		Authz: s.authz,
	}).Register(s.mux)

	(&storage.Handler{
		Store:      s.store,
		Auth:       s.authn,
		Authz:      s.authz,
		ListenAddr: s.cfg.ListenAddr,
	}).Register(s.mux)

	(&table.Handler{
		Store: s.store,
		Auth:  s.authn,
	}).Register(s.mux)

	(&servicebus.Handler{
		Store:          s.store,
		Auth:           s.authn,
		Authz:          s.authz,
		AMQPListenAddr: s.cfg.AMQPListenAddr,
	}).Register(s.mux)
}
