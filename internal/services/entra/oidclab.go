package entra

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (s *Service) ensureOIDCLabKey() (string, *rsa.PrivateKey, error) {
	return s.Store.EnsureOIDCLabSigningKey()
}

func (s *Service) handleLabOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := s.labOIDCIssuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/keys",
		"token_endpoint":                        iss + "/token",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
	})
}

func (s *Service) handleLabJWKS(w http.ResponseWriter, r *http.Request) {
	kid, priv, err := s.ensureOIDCLabKey()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
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
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": kid,
			"alg": "RS256",
			"n":   n,
			"e":   e,
		}},
	})
}

func (s *Service) handleLabOIDCToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	grant := strings.TrimSpace(r.Form.Get("grant_type"))
	if grant != "" && grant != "client_credentials" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be client_credentials")
		return
	}
	subject := strings.TrimSpace(r.Form.Get("subject"))
	if subject == "" {
		subject = strings.TrimSpace(r.Form.Get("sub"))
	}
	if subject == "" {
		azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return
	}
	audience := strings.TrimSpace(r.Form.Get("audience"))
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("aud"))
	}
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("resource"))
	}
	if audience == "" {
		audience = strings.TrimSpace(r.Form.Get("scope"))
		audience = strings.TrimSuffix(audience, "/.default")
		if i := strings.IndexByte(audience, ' '); i > 0 {
			audience = audience[:i]
		}
	}
	token, err := s.MintLabOIDCAssertion(subject, audience)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":   "Bearer",
		"expires_in":   600,
		"access_token": token,
		"id_token":     token,
	})
}

// MintLabOIDCAssertion issues a JWT from the lab OIDC issuer for WIF tests.
func (s *Service) MintLabOIDCAssertion(subject, audience string) (string, error) {
	return s.MintLabOIDCAssertionClaims(subject, audience, nil)
}

// MintLabOIDCAssertionClaims issues a lab OIDC JWT and merges extra claims (sub/iss/aud stay as given).
func (s *Service) MintLabOIDCAssertionClaims(subject, audience string, extra map[string]any) (string, error) {
	kid, priv, err := s.ensureOIDCLabKey()
	if err != nil {
		return "", err
	}
	if audience == "" {
		audience = "api://AzureADTokenExchange"
	}
	now := s.now()
	claims := map[string]any{
		"iss": s.labOIDCIssuer(),
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	for k, v := range extra {
		if k == "iss" || k == "sub" || k == "aud" {
			continue
		}
		claims[k] = v
	}
	return authn.EncodeRS256JWT(priv, kid, claims)
}
