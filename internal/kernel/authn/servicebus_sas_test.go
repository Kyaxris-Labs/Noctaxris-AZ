package authn_test

import (
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestServiceBusSASSignAndVerify(t *testing.T) {
	key := "lab-namespace-key"
	uri := "sb://ns1.servicebus.windows.net/orders"
	tok := authn.SignServiceBusSAS(key, "RootManageSharedAccessKey", uri, time.Now().UTC().Add(time.Hour))
	if tok == "" {
		t.Fatal("empty token")
	}
	if !authn.VerifyServiceBusSAS(key, tok, "", time.Now().UTC()) {
		t.Fatal("verify without resource check")
	}
	if !authn.VerifyServiceBusSAS(key, tok, uri, time.Now().UTC()) {
		t.Fatal("verify with resource check")
	}
	if authn.VerifyServiceBusSAS(key, tok, "sb://other.servicebus.windows.net/", time.Now().UTC()) {
		t.Fatal("wrong resource accepted")
	}
	if authn.VerifyServiceBusSAS("wrong", tok, "", time.Now().UTC()) {
		t.Fatal("wrong key accepted")
	}
	expired := authn.SignServiceBusSAS(key, "Root", uri, time.Now().UTC().Add(-time.Minute))
	if authn.VerifyServiceBusSAS(key, expired, "", time.Now().UTC()) {
		t.Fatal("expired accepted")
	}
}
