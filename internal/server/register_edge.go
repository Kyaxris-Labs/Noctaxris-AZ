package server

import (
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/apim"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appgateway"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/appservice"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/containerapps"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/dns"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/email"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/frontdoor"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/loadbalancer"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/logic"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/openai"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/signalr"
)

func (s *Server) registerEdge() {
	(&apim.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&email.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&appservice.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&containerapps.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&logic.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&dns.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&loadbalancer.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&appgateway.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&frontdoor.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&openai.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
	(&signalr.Handler{Store: s.store, Auth: s.authn, Authz: s.authz}).Register(s.mux)
}
