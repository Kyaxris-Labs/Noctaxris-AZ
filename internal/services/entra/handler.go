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
	AuditNow   func() time.Time

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

func (s *Service) auditNow() time.Time {
	if s.AuditNow != nil {
		return s.AuditNow().UTC()
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

// loginTenants are literal path prefixes. Wildcards conflict with Graph /v1.0/{path...}.
func (s *Service) loginTenants() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	add(s.TenantID)
	add(s.appTenant())
	add("common")
	add("organizations")
	return out
}

// Mount registers Entra OIDC, token, Graph, AAD Graph, and lab OIDC issuer routes.
func (s *Service) Mount(mux *http.ServeMux) {
	for _, tenant := range s.loginTenants() {
		t := tenant
		mux.HandleFunc("GET /"+t+"/v2.0/.well-known/openid-configuration", s.handleOIDCDiscovery)
		mux.HandleFunc("GET /"+t+"/.well-known/openid-configuration", s.handleOIDCDiscovery)
		mux.HandleFunc("GET /"+t+"/discovery/v2.0/keys", s.handleJWKS)
		mux.HandleFunc("GET /"+t+"/discovery/keys", s.handleJWKS)
		mux.HandleFunc("POST /"+t+"/oauth2/v2.0/token", s.handleToken)
		mux.HandleFunc("POST /"+t+"/oauth2/token", s.handleToken)
		mux.HandleFunc("POST /"+t+"/oauth2/v2.0/devicecode", s.handleDeviceCode)
		mux.HandleFunc("POST /"+t+"/oauth2/devicecode", s.handleDeviceCode)
		mux.HandleFunc("GET /"+t+"/tenantDetails", s.handleAADTenantDetails)
		mux.HandleFunc("GET /"+t+"/users", s.handleAADUsers)
		mux.HandleFunc("GET /"+t+"/directoryRoles", s.handleAADDirectoryRoles)
	}
	mux.HandleFunc("GET /_noctaxris-az/oidc-lab/.well-known/openid-configuration", s.handleLabOIDCDiscovery)
	mux.HandleFunc("GET /_noctaxris-az/oidc-lab/keys", s.handleLabJWKS)
	mux.HandleFunc("POST /_noctaxris-az/oidc-lab/token", s.handleLabOIDCToken)

	s.mountGraph(mux)
	s.mountIAMPortal(mux)
	s.mountProvisioningSOAP(mux)
}

func (s *Service) pathTenant(r *http.Request) string {
	t := strings.TrimSpace(r.PathValue("tenant"))
	if t == "" {
		p := strings.Trim(r.URL.Path, "/")
		if i := strings.IndexByte(p, '/'); i > 0 {
			t = p[:i]
		}
	}
	if t == "" || strings.EqualFold(t, "common") || strings.EqualFold(t, "organizations") {
		return s.appTenant()
	}
	return t
}

func (s *Service) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	tenant := s.pathTenant(r)
	base := s.base()
	v2 := strings.Contains(r.URL.Path, "/v2.0/")
	issuer := base + "/" + tenant
	tokenPath := base + "/" + tenant + "/oauth2/token"
	jwksPath := base + "/" + tenant + "/discovery/keys"
	if v2 {
		issuer += "/v2.0"
		tokenPath = base + "/" + tenant + "/oauth2/v2.0/token"
		jwksPath = base + "/" + tenant + "/discovery/v2.0/keys"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_endpoint":                        tokenPath,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"},
		"jwks_uri":                              jwksPath,
		"issuer":                                issuer,
		"authorization_endpoint":                base + "/" + tenant + "/oauth2/v2.0/authorize",
		"device_authorization_endpoint":         base + "/" + tenant + "/oauth2/v2.0/devicecode",
		"response_types_supported":              []string{"code", "id_token", "token", "code id_token"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"pairwise"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
	})
}

func (s *Service) handleJWKS(w http.ResponseWriter, r *http.Request) {
	kid, priv, err := s.ensureKey()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	tenant := s.pathTenant(r)
	if tenant == "" {
		tenant = s.appTenant()
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
	s.dispatchToken(w, r)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
