package authn

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTVerifier validates lab-issued RS256 access tokens.
type JWTVerifier interface {
	VerifyAccessToken(token string, now time.Time) (principalID string, ok bool, err error)
}

// AuthenticateToken validates a raw bearer token string.
func (a *Authenticator) AuthenticateToken(token string) (Principal, error) {
	if a.RootAccessToken != "" && token == a.RootAccessToken {
		id := a.RootClientID
		if id == "" {
			id = "root"
		}
		return Principal{ID: id, IsRoot: true}, nil
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now()
	}
	if a.Tokens != nil {
		id, ok, err := a.Tokens.LookupAccessToken(HashToken(token), now)
		if err != nil {
			return Principal{}, err
		}
		if ok && id != "" {
			return Principal{ID: id, IsRoot: false}, nil
		}
	}
	if a.JWT != nil {
		id, ok, err := a.JWT.VerifyAccessToken(token, now)
		if err != nil {
			return Principal{}, err
		}
		if ok && id != "" {
			return Principal{ID: id, IsRoot: false}, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}

// EncodeRS256JWT builds a compact RS256 JWT.
func EncodeRS256JWT(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// VerifyRS256JWT verifies signature and exp, returning the claims map.
func VerifyRS256JWT(pub *rsa.PublicKey, token string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt")
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg")
	}
	cb, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, err
	}
	if expRaw, ok := claims["exp"]; ok {
		var exp int64
		switch v := expRaw.(type) {
		case float64:
			exp = int64(v)
		case json.Number:
			n, _ := v.Int64()
			exp = n
		}
		if exp > 0 && now.Unix() > exp {
			return nil, fmt.Errorf("token expired")
		}
	}
	return claims, nil
}

// PrincipalFromJWTClaims picks oid, then sub, then appid/azp.
func PrincipalFromJWTClaims(claims map[string]any) string {
	for _, k := range []string{"oid", "sub", "appid", "azp"} {
		if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
