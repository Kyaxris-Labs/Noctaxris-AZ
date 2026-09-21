package entra_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
)

func TestFederatedCredentialMatchPrefersClientApplication(t *testing.T) {
	st := openStore(t)
	svc, mux := newEntraMux(t, st)
	issuer := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	aud := "api://AzureADTokenExchange"
	sub := "repo:shared/subject"

	seededObj := "55555555-5555-5555-5555-555555555555"
	seededApp := "66666666-6666-6666-6666-666666666666"
	thiefAppID, err := st.UpsertEntraApp(config.DefaultTenantID, "", "thief")
	if err != nil {
		t.Fatal(err)
	}
	thief, ok, err := st.GetEntraApp(config.DefaultTenantID, thiefAppID)
	if err != nil || !ok {
		t.Fatalf("thief app ok=%v err=%v", ok, err)
	}

	if _, err := st.CreateFIC(thief.ObjectID, "thief", issuer, sub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFIC(seededObj, "owner", issuer, sub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}

	assertWIF(t, svc, mux, seededApp, sub, true)
	assertWIF(t, svc, mux, thiefAppID, sub, true)

	otherSub := "repo:other/only-thief"
	if _, err := st.CreateFIC(thief.ObjectID, "thief-only", issuer, otherSub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	assertWIF(t, svc, mux, seededApp, otherSub, false)
	assertWIF(t, svc, mux, thiefAppID, otherSub, true)
}
