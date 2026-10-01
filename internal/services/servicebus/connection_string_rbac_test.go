package servicebus_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/servicebus"
)

func TestConnectionStringRequiresListKeysAction(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus"); err != nil {
		t.Fatal(err)
	}
	scope := "/subscriptions/sub/resourceGroups/rg"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-reader", Scope: scope, RoleDefinitionID: authz.RoleReader,
		PrincipalID: "sp-reader", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &servicebus.Handler{
		Store:          st,
		Auth:           &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz:          &authz.Evaluator{Assignments: st},
		AMQPListenAddr: "127.0.0.1:5672",
	}
	mux := http.NewServeMux()
	h.Register(mux)

	readerTok, _, err := es.MintAccessToken("sp-reader", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := http.NewRequest(http.MethodGet,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns1/connectionString", nil)
	cs.Header.Set("Authorization", "Bearer "+readerTok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, cs)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reader connectionString status=%d body=%s", rec.Code, rec.Body.String())
	}

	root, _ := http.NewRequest(http.MethodGet,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns1/connectionString", nil)
	root.Header.Set("Authorization", "Bearer root-token")
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, root)
	if rrec.Code != http.StatusOK {
		t.Fatalf("root connectionString status=%d body=%s", rrec.Code, rrec.Body.String())
	}
	if !strings.Contains(rrec.Body.String(), "SharedAccessKey=") {
		t.Fatalf("root body missing key: %s", rrec.Body.String())
	}
}
