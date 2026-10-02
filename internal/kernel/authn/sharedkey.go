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

// StorageStringToSign builds a lab Shared Key Lite-shaped string-to-sign:
// Verb, Content-MD5, Content-Type, Date (x-ms-date preferred), canonicalized
// x-ms-* headers, then the request path. Lab-safe subset of Azure Shared Key Lite.
func StorageStringToSign(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	date := strings.TrimSpace(r.Header.Get("x-ms-date"))
	if date == "" {
		date = strings.TrimSpace(r.Header.Get("Date"))
	}
	return strings.Join([]string{
		strings.ToUpper(r.Method),
		strings.TrimSpace(r.Header.Get("Content-MD5")),
		strings.TrimSpace(r.Header.Get("Content-Type")),
		date,
		canonicalizeStorageMSHeaders(r),
		r.URL.Path,
	}, "\n")
}

func canonicalizeStorageMSHeaders(r *http.Request) string {
	if r == nil {
		return ""
	}
	type kv struct{ k, v string }
	var ms []kv
	for k, vals := range r.Header {
		lk := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(lk, "x-ms-") {
			continue
		}
		ms = append(ms, kv{k: lk, v: strings.Join(vals, ",")})
	}
	if len(ms) == 0 {
		return ""
	}
	// Insertion sort keeps the stdlib-only dependency surface small.
	for i := 1; i < len(ms); i++ {
		j := i
		for j > 0 && ms[j-1].k > ms[j].k {
			ms[j-1], ms[j] = ms[j], ms[j-1]
			j--
		}
	}
	parts := make([]string, 0, len(ms))
	for _, h := range ms {
		parts = append(parts, h.k+":"+strings.TrimSpace(h.v))
	}
	return strings.Join(parts, "\n")
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
				// Create Table requires account/service SAS Create (c), not Add/Write.
				return has("c")
			}
			return has("u")
		case "MERGE":
			return has("u")
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
