package entra

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"net/http"
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

// MintLabOIDCAssertion issues a JWT from the lab OIDC issuer for WIF tests.
func (s *Service) MintLabOIDCAssertion(subject, audience string) (string, error) {
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
	return authn.EncodeRS256JWT(priv, kid, claims)
}
