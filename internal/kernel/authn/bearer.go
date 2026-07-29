package authn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ErrUnauthenticated is returned when credentials are missing or invalid.
var ErrUnauthenticated = errors.New("unauthenticated")

// Principal is an authenticated caller.
type Principal struct {
	ID     string
	IsRoot bool
}

// TokenLookup resolves a registered access token hash to a principal id.
type TokenLookup interface {
	LookupAccessToken(tokenHash string, now time.Time) (principalID string, ok bool, err error)
}

// Authenticator validates Authorization: Bearer tokens.
type Authenticator struct {
	RootClientID    string
	RootAccessToken string
	Tokens          TokenLookup
	Now             func() time.Time
}

var oauthTokenPath = regexp.MustCompile(`(?i)^/[^/]+/oauth2/v2\.0/token$`)

// AuthenticateRequest extracts and validates the Bearer token from r.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (Principal, error) {
	raw := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimSpace(strings.TrimPrefix(raw, prefix))
	if token == "" {
		return Principal{}, ErrUnauthenticated
	}
	return a.AuthenticateToken(token)
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
	if a.Tokens == nil {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now()
	}
	id, ok, err := a.Tokens.LookupAccessToken(HashToken(token), now)
	if err != nil {
		return Principal{}, err
	}
	if !ok || id == "" {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{ID: id, IsRoot: false}, nil
}

// HashToken returns the hex-encoded SHA-256 digest of token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IsPublicPath reports whether path skips authentication.
func IsPublicPath(path string) bool {
	switch path {
	case "/_noctaxris-az/health", "/_noctaxris-az/ready", "/_noctaxris-az/version":
		return true
	default:
		return oauthTokenPath.MatchString(path)
	}
}
