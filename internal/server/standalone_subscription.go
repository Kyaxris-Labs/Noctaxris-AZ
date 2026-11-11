package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const standaloneSubscriptionSeedPath = "/_noctaxris-az/lab/subscriptions:seedStandalone"

func (s *Server) registerLabStandalone() {
	if s == nil || !s.cfg.LabStandalone {
		return
	}
	s.mux.HandleFunc("POST "+standaloneSubscriptionSeedPath, s.handleSeedStandaloneSubscription)
}

func (s *Server) handleSeedStandaloneSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !s.cfg.LabStandalone {
		http.NotFound(w, r)
		return
	}
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		azerrors.Unauthenticated(w, "")
		return
	}
	if !p.IsRoot {
		azerrors.WriteARM(w, http.StatusForbidden, "AccessDenied", "Standalone subscription seed requires Bearer root")
		return
	}
	name, err := standaloneSeedName(r)
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	seeded, err := s.store.SeedStandaloneSubscription(store.StandaloneSeedRequest{
		SeedName:          name,
		TenantID:          s.cfg.TenantID,
		LabSubscriptionID: s.cfg.SubscriptionID,
		RootClientID:      s.cfg.RootClientID,
	}, s.mintStandaloneAccessToken)
	if err != nil {
		var nameErr *store.StandaloneSeedNameError
		if errors.As(err, &nameErr) {
			azerrors.BadRequest(w, nameErr.Error())
			return
		}
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", "Unable to seed the standalone subscription.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subscriptionId":    seeded.SubscriptionID,
		"tenantId":          seeded.TenantID,
		"userId":            seeded.UserID,
		"userPrincipalName": seeded.UserPrincipalName,
		"accessToken":       seeded.AccessToken,
	})
}

func standaloneSeedName(r *http.Request) (string, error) {
	if r.Body == nil {
		return store.NormalizeStandaloneSeedName("")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", errors.New("unable to read body")
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return store.NormalizeStandaloneSeedName("")
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", errors.New("request body must be a JSON object")
	}
	return store.NormalizeStandaloneSeedName(req.Name)
}

// mintStandaloneAccessToken uses MintAccessToken with the ARM audience.
// If the compact token equals the root credential, the hash is discarded and
// the issuer clock moves forward one second so the next mint differs.
func (s *Server) mintStandaloneAccessToken(userID string) (string, error) {
	if s == nil || s.entra == nil {
		return "", errors.New("standalone subscription: token issuer is not configured")
	}
	es := s.entra
	prev := es.Now
	base := time.Now().UTC()
	if prev != nil {
		base = prev()
	}
	defer func() { es.Now = prev }()
	for i := 0; i < 5; i++ {
		attempt := base.Add(time.Duration(i) * time.Second)
		es.Now = func() time.Time { return attempt }
		token, _, err := es.MintAccessToken(userID, authn.AudienceARM)
		if err != nil {
			return "", err
		}
		if s.cfg.RootAccessToken == "" || token != s.cfg.RootAccessToken {
			return token, nil
		}
		if err := s.store.DeleteAccessToken(authn.HashToken(token)); err != nil {
			return "", err
		}
	}
	return "", errors.New("standalone subscription: minted token matched the root credential")
}
