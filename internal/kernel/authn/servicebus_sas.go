package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SignServiceBusSAS builds a lab SharedAccessSignature token for AMQP theatre.
// stringToSign is resourceURI + "\n" + expiryUnix, HMAC-SHA256 with the key bytes.
func SignServiceBusSAS(accountKey, keyName, resourceURI string, expiry time.Time) string {
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		keyName = "RootManageSharedAccessKey"
	}
	resourceURI = strings.TrimSpace(resourceURI)
	if accountKey == "" || resourceURI == "" || expiry.IsZero() {
		return ""
	}
	se := strconv.FormatInt(expiry.UTC().Unix(), 10)
	sig := signServiceBusSAS(accountKey, resourceURI, se)
	v := url.Values{}
	v.Set("sr", resourceURI)
	v.Set("sig", sig)
	v.Set("se", se)
	v.Set("skn", keyName)
	return "SharedAccessSignature " + v.Encode()
}

// VerifyServiceBusSAS verifies a SharedAccessSignature token against the namespace key.
// resourceURI, when non-empty, must match the signed sr.
func VerifyServiceBusSAS(accountKey, token string, resourceURI string, now time.Time) bool {
	accountKey = strings.TrimSpace(accountKey)
	token = strings.TrimSpace(token)
	if accountKey == "" || token == "" {
		return false
	}
	token = strings.TrimPrefix(token, "SharedAccessSignature ")
	token = strings.TrimPrefix(token, "sharedaccesssignature ")
	vals, err := url.ParseQuery(token)
	if err != nil {
		return false
	}
	sr := strings.TrimSpace(vals.Get("sr"))
	sig := strings.TrimSpace(vals.Get("sig"))
	se := strings.TrimSpace(vals.Get("se"))
	if sr == "" || sig == "" || se == "" {
		return false
	}
	if resourceURI != "" && !strings.EqualFold(strings.TrimRight(sr, "/"), strings.TrimRight(resourceURI, "/")) {
		return false
	}
	expUnix, err := strconv.ParseInt(se, 10, 64)
	if err != nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if !now.Before(time.Unix(expUnix, 0).UTC()) {
		return false
	}
	want := signServiceBusSAS(accountKey, sr, se)
	return hmac.Equal([]byte(want), []byte(sig))
}

func signServiceBusSAS(accountKey, resourceURI, se string) string {
	sts := resourceURI + "\n" + se
	mac := hmac.New(sha256.New, []byte(accountKey))
	_, _ = mac.Write([]byte(sts))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
