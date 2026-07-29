package entra

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const defaultExpiresIn = 3600

// Service serves Microsoft Entra ID OAuth2 token theatre.
type Service struct {
	Store    *store.Store
	TenantID string
	Now      func() time.Time
}

// Mount registers Entra routes on mux.
func (s *Service) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", s.handleToken)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) handleToken(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		azerrors.BadRequest(w, "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		azerrors.BadRequest(w, "invalid form body")
		return
	}
	grant := strings.TrimSpace(r.Form.Get("grant_type"))
	if grant != "client_credentials" {
		azerrors.BadRequest(w, "grant_type must be client_credentials")
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" {
		azerrors.BadRequest(w, "client_id is required")
		return
	}

	token, err := newAccessToken()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	expiry := s.now().Add(time.Duration(defaultExpiresIn) * time.Second)
	if err := s.Store.PutAccessToken(authn.HashToken(token), clientID, expiry); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token_type":     "Bearer",
		"expires_in":     defaultExpiresIn,
		"ext_expires_in": defaultExpiresIn,
		"access_token":   token,
	})
}

func newAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
