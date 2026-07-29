package entra

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const defaultExpiresIn = 3600

// Service serves Microsoft Entra ID OAuth2 / OIDC theatre.
type Service struct {
	Store      *store.Store
	TenantID   string
	PublicBase string // e.g. http://127.0.0.1:4599
	Now        func() time.Time

	mu   sync.Mutex
	kid  string
	priv *rsa.PrivateKey
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Service) base() string {
	b := strings.TrimRight(strings.TrimSpace(s.PublicBase), "/")
	if b == "" {
		b = "http://127.0.0.1:4599"
	}
	return b
}

func (s *Service) ensureKey() (string, *rsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv != nil && s.kid != "" {
		return s.kid, s.priv, nil
	}
	kid, priv, err := s.Store.EnsureEntraSigningKey()
	if err != nil {
		return "", nil, err
	}
	s.kid, s.priv = kid, priv
	return kid, priv, nil
}

// VerifyAccessToken implements authn.JWTVerifier.
func (s *Service) VerifyAccessToken(token string, now time.Time) (principalID string, ok bool, err error) {
	_, priv, err := s.ensureKey()
	if err != nil {
		return "", false, err
	}
	claims, err := authn.VerifyRS256JWT(&priv.PublicKey, token, now)
	if err != nil {
		return "", false, nil
	}
	id := authn.PrincipalFromJWTClaims(claims)
	if id == "" {
		return "", false, nil
	}
	return id, true, nil
}

// MintAccessToken issues an RS256 lab JWT and records its hash for opaque lookup compatibility.
func (s *Service) MintAccessToken(principalID, audience string) (token string, expiresIn int, err error) {
	kid, priv, err := s.ensureKey()
	if err != nil {
		return "", 0, err
	}
	if audience == "" {
		audience = "https://management.azure.com"
	}
	now := s.now()
	exp := now.Add(time.Duration(defaultExpiresIn) * time.Second)
	iss := s.base() + "/" + s.TenantID + "/v2.0"
	claims := map[string]any{
		"aud":   audience,
		"iss":   iss,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   exp.Unix(),
		"sub":   principalID,
		"oid":   principalID,
		"tid":   s.TenantID,
		"appid": principalID,
		"azp":   principalID,
		"ver":   "2.0",
	}
	token, err = authn.EncodeRS256JWT(priv, kid, claims)
	if err != nil {
		return "", 0, err
	}
	if err := s.Store.PutAccessToken(authn.HashToken(token), principalID, exp); err != nil {
		return "", 0, err
	}
	return token, defaultExpiresIn, nil
}

// Mount registers Entra routes on mux.
func (s *Service) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", s.handleOIDCDiscovery)
	mux.HandleFunc("GET /{tenant}/discovery/v2.0/keys", s.handleJWKS)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", s.handleToken)
}

func (s *Service) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	base := s.base()
	issuer := base + "/" + tenant + "/v2.0"
	// Shape mirrors Microsoft identity platform OIDC discovery (lab issuer/base).
	// See https://learn.microsoft.com/entra/identity-platform/v2-protocols-oidc
	writeJSON(w, http.StatusOK, map[string]any{
		"token_endpoint":                       base + "/" + tenant + "/oauth2/v2.0/token",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"},
		"jwks_uri":                             base + "/" + tenant + "/discovery/v2.0/keys",
		"issuer":                               issuer,
		"authorization_endpoint":               base + "/" + tenant + "/oauth2/v2.0/authorize",
		"response_types_supported":             []string{"code", "id_token", "token", "code id_token"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":              []string{"pairwise"},
		"scopes_supported":                     []string{"openid", "profile", "email", "offline_access"},
	})
}

func (s *Service) handleJWKS(w http.ResponseWriter, r *http.Request) {
	kid, priv, err := s.ensureKey()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	tenant := r.PathValue("tenant")
	if tenant == "" {
		tenant = s.TenantID
	}
	pub := priv.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(pub.E))
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes[i:])
	issuer := s.base() + "/" + tenant + "/v2.0"
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty":    "RSA",
			"use":    "sig",
			"kid":    kid,
			"alg":    "RS256",
			"n":      n,
			"e":      e,
			"issuer": issuer,
		}},
	})
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
	audience := strings.TrimSpace(r.Form.Get("scope"))
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("resource"))
	}
	audience = strings.TrimSuffix(audience, "/.default")
	token, expiresIn, err := s.MintAccessToken(clientID, audience)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":     "Bearer",
		"expires_in":     expiresIn,
		"ext_expires_in": expiresIn,
		"access_token":   token,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
