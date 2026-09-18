package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// ParseSharedKeyAuthorization parses Authorization: SharedKey account:signature.
func ParseSharedKeyAuthorization(header string) (account, signature string, ok bool) {
	const prefix = "SharedKey "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// VerifyStorageSharedKey verifies a lab-lite Shared Key signature.
// stringToSign is HMAC-SHA256 with the account key (decoded from base64 if possible, else raw).
func VerifyStorageSharedKey(accountKey, stringToSign, providedSig string) bool {
	if providedSig == "" {
		return false
	}
	key := decodeAccountKey(accountKey)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(providedSig))
}

func decodeAccountKey(accountKey string) []byte {
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return []byte(accountKey)
	}
	return key
}

// StorageStringToSign builds a simplified lab string-to-sign (method + path).
func StorageStringToSign(r *http.Request) string {
	return strings.ToUpper(r.Method) + "\n" + r.URL.Path
}

// HasSAS reports whether the request carries SAS query parameters (non-empty sig and se).
// Presence is not authorization. Call VerifyStorageSAS against the account key.
func HasSAS(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	q := r.URL.Query()
	return q.Get("sig") != "" && q.Get("se") != ""
}

// StorageSASStringToSign builds the lab SAS HMAC input: sp, st, se, canonicalized path.
// sp and se are inside the signed string so they cannot be swapped after signing.
func StorageSASStringToSign(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	q := r.URL.Query()
	return strings.Join([]string{
		q.Get("sp"),
		q.Get("st"),
		q.Get("se"),
		r.URL.Path,
	}, "\n")
}

// ParseSASExpiry parses Azure Storage SAS se/st timestamps. Unix-only values are rejected.
func ParseSASExpiry(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04Z",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// SASPermits reports whether signed permissions sp allow method on path.
func SASPermits(sp, method, path string) bool {
	sp = strings.ToLower(strings.TrimSpace(sp))
	if sp == "" {
		return false
	}
	method = strings.ToUpper(method)
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return false
	}
	svc := strings.ToLower(parts[0])
	depth := len(parts)
	has := func(letters string) bool {
		for _, c := range letters {
			if strings.ContainsRune(sp, c) {
				return true
			}
		}
		return false
	}
	switch svc {
	case "blob":
		switch method {
		case http.MethodGet, http.MethodHead:
			if depth <= 3 {
				return has("l")
			}
			return has("r")
		case http.MethodPut:
			if depth <= 3 {
				return has("cw")
			}
			return has("wca")
		case http.MethodDelete:
			return has("d")
		case http.MethodPost:
			return has("aw")
		default:
			return false
		}
	case "queue":
		switch method {
		case http.MethodGet, http.MethodHead:
			return has("rp")
		case http.MethodPut:
			return has("cw")
		case http.MethodPost:
			return has("a")
		case http.MethodDelete:
			return has("d")
		default:
			return false
		}
	case "table":
		switch method {
		case http.MethodGet, http.MethodHead:
			return has("r")
		case http.MethodPut:
			if depth <= 3 {
				return has("caw")
			}
			return has("uw")
		case "MERGE":
			return has("uw")
		case http.MethodPost:
			return has("a")
		case http.MethodDelete:
			return has("d")
		default:
			return false
		}
	default:
		return false
	}
}

// VerifyStorageSAS HMAC-verifies sig with the storage account key, parses se as expiry,
// rejects unparseable or elapsed se, and honors sp. Missing key material fails closed.
func VerifyStorageSAS(accountKey string, r *http.Request, now time.Time) bool {
	if accountKey == "" || r == nil || r.URL == nil {
		return false
	}
	q := r.URL.Query()
	sig := strings.TrimSpace(q.Get("sig"))
	se := strings.TrimSpace(q.Get("se"))
	if sig == "" || se == "" {
		return false
	}
	expiry, ok := ParseSASExpiry(se)
	if !ok {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if !now.Before(expiry) {
		return false
	}
	if st := strings.TrimSpace(q.Get("st")); st != "" {
		start, ok := ParseSASExpiry(st)
		if !ok || now.Before(start) {
			return false
		}
	}
	if !SASPermits(q.Get("sp"), r.Method, r.URL.Path) {
		return false
	}
	return VerifyStorageSharedKey(accountKey, StorageSASStringToSign(r), sig)
}
