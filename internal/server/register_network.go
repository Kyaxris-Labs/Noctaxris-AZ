package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/aks"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/virtualmachines"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/network"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/nic"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/nsg"
)

func (s *Server) registerNetwork() {
	(&network.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&nsg.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&nic.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&virtualmachines.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&aks.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
}
