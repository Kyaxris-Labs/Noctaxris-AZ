package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
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
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		key = []byte(accountKey)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(providedSig))
}

// StorageStringToSign builds a simplified lab string-to-sign (method + path).
func StorageStringToSign(r *http.Request) string {
	return strings.ToUpper(r.Method) + "\n" + r.URL.Path
}

// HasSAS reports whether the request carries a SAS query token (lab: sig= present).
func HasSAS(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("sig") != "" && q.Get("se") != ""
}
