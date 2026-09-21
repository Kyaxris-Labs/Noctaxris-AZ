package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/acr"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/azuresql"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/cosmos"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventgrid"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/keyvault"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/postgres"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/rediscache"
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

	(&eventhubs.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&eventgrid.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&cosmos.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&azuresql.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&postgres.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&rediscache.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&acr.Handler{Store: s.store, Auth: s.authn, Authz: s.authz, SubscriptionID: s.cfg.SubscriptionID}).Register(s.mux)
}
