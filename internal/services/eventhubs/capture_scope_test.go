package eventhubs_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEventHubsCaptureIsolatedByResourceGroup(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.UpsertEventHubsNamespace("s", "rg-attacker", "shared", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEventHubsNamespace("s", "rg-victim", "shared", "eastus"); err != nil {
		t.Fatal(err)
	}
	victimKey := store.EventHubNamespaceKey("s", "rg-victim", "shared")
	if err := st.CreateEventHub(victimKey, "hub1", 2); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueEventHub(victimKey, "hub1", "0", []byte("victim-secret")); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-att", Scope: "/subscriptions/s/resourceGroups/rg-attacker",
		RoleDefinitionID: authz.RoleEventHubsDataReceiver,
		PrincipalID:      "eh-recv", PrincipalType: "User",
	}); err != nil {
		t.Fatal(err)
	}

	h := &eventhubs.Handler{
		Store: st,
		Auth: &authn.Authenticator{
			RootClientID: "r", RootAccessToken: "tok",
			Tokens: directoryTokens{id: "eh-recv"},
		},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/eventhubs/shared/hubs/hub1/capturedEvents", nil)
	req.Header.Set("Authorization", "Bearer directory-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("attacker capture status %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), "victim-secret") {
		t.Fatalf("cross-RG capture leak: %s", body)
	}
}
