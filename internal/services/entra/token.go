package entra

import (
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantOBO        = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	assertionType   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	refreshTTL      = 24 * time.Hour
	deviceTTL       = 15 * time.Minute
)

func (s *Service) dispatchToken(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	grant := strings.TrimSpace(r.Form.Get("grant_type"))
	switch grant {
	case "client_credentials":
		s.tokenClientCredentials(w, r)
	case "password":
		s.tokenPassword(w, r)
	case "refresh_token":
		s.tokenRefresh(w, r)
	case grantDeviceCode:
		s.tokenDeviceCode(w, r)
	case grantOBO:
		azerrors.WriteOAuth(w, http.StatusBadRequest, "unsupported_grant_type", "On-Behalf-Of jwt-bearer is not implemented; use client_credentials with client_assertion for federation")
	default:
		azerrors.WriteOAuth(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be client_credentials, password, refresh_token, or device_code")
	}
}

func (s *Service) tokenAudience(r *http.Request) string {
	audience := strings.TrimSpace(r.Form.Get("scope"))
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("resource"))
	}
	audience = strings.TrimSuffix(audience, "/.default")
	if i := strings.IndexByte(audience, ' '); i > 0 {
		audience = audience[:i]
	}
	return audience
}

func (s *Service) writeToken(w http.ResponseWriter, r *http.Request, principalID, audience string, withRefresh bool) {
	token, expiresIn, err := s.MintAccessToken(principalID, audience)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	body := map[string]any{
		"token_type":     "Bearer",
		"expires_in":     expiresIn,
		"ext_expires_in": expiresIn,
		"access_token":   token,
	}
	if !strings.Contains(r.URL.Path, "/v2.0/") && audience != "" {
		body["resource"] = audience
	}
	if withRefresh {
		rt := store.RandomToken(32)
		exp := s.now().Add(refreshTTL)
		if err := s.Store.PutRefreshToken(authn.HashToken(rt), principalID, exp); err != nil {
			azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		body["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Service) tokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	assertion := strings.TrimSpace(r.Form.Get("client_assertion"))
	assertionTyp := strings.TrimSpace(r.Form.Get("client_assertion_type"))
	if assertion != "" {
		if assertionTyp != "" && assertionTyp != assertionType {
			azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_client", "client_assertion_type must be "+assertionType)
			return
		}
		id, ok := s.verifyClientAssertion(w, r, clientID, assertion)
		if !ok {
			return
		}
		clientID = id
	}
	if clientID == "" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	s.writeToken(w, r, clientID, s.tokenAudience(r), false)
}

func (s *Service) tokenPassword(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))
	if username == "" || password == "" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_grant", "username and password are required")
		return
	}
	principal := username
	if u, ok, err := s.Store.GetDirectoryUser(username); err == nil && ok {
		principal = u.ID
	}
	s.writeToken(w, r, principal, s.tokenAudience(r), true)
}

func (s *Service) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	rt := strings.TrimSpace(r.Form.Get("refresh_token"))
	if rt == "" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	id, ok, err := s.Store.LookupRefreshToken(authn.HashToken(rt), s.now())
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !ok {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_grant", "refresh_token is invalid or expired")
		return
	}
	s.writeToken(w, r, id, s.tokenAudience(r), true)
}

func (s *Service) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	code := store.RandomToken(24)
	userCode := strings.ToUpper(store.RandomToken(4) + "-" + store.RandomToken(4))
	principal := "11111111-1111-1111-1111-111111111111"
	if err := s.Store.PutDeviceCode(code, principal, s.now().Add(deviceTTL)); err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      code,
		"user_code":        userCode,
		"verification_uri": s.base() + "/device",
		"expires_in":       int(deviceTTL.Seconds()),
		"interval":         5,
		"message":          "lab device code auto-succeeds on token exchange",
	})
}

func (s *Service) tokenDeviceCode(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.Form.Get("device_code"))
	if code == "" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}
	id, ok, err := s.Store.LookupDeviceCode(code, s.now())
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !ok {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_grant", "device_code is invalid or expired")
		return
	}
	s.writeToken(w, r, id, s.tokenAudience(r), true)
}
