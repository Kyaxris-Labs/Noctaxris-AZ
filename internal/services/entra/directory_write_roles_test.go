package entra_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestDirectoryRoleMemberAddRequiresGlobalAdmin(t *testing.T) {
	st := openStore(t)

	low := graphServerAs(t, st, authn.Principal{ID: "attacker", Audiences: []string{authn.AudienceGraph}})
	denyReq, _ := http.NewRequest(http.MethodPost,
		low.URL+"/v1.0/directoryRoles/88888888-8888-8888-8888-888888888888/members/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/attacker"}`))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRes, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, denyRes)
	if denyRes.StatusCode != http.StatusForbidden {
		t.Fatalf("low privilege role add status=%d", denyRes.StatusCode)
	}

	admin := graphServerAs(t, st, authn.Principal{
		ID: "11111111-1111-1111-1111-111111111111", Audiences: []string{authn.AudienceGraph},
	})
	okReq, _ := http.NewRequest(http.MethodPost,
		admin.URL+"/v1.0/directoryRoles/99999999-9999-9999-9999-999999999999/members/$ref",
		strings.NewReader(`{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/22222222-2222-2222-2222-222222222222"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(okReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(t, okRes)
	if okRes.StatusCode != http.StatusNoContent {
		t.Fatalf("global admin role add status=%d", okRes.StatusCode)
	}
}
