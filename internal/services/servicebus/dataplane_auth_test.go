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

func TestServiceBusHTTPRejectsAnyBearer(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusQueue("ns1", "q1"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &servicebus.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	graphTok, _, err := es.MintAccessToken("sp-lab", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	post, _ := http.NewRequest(http.MethodPost, "/servicebus/ns1/queues/q1/messages", strings.NewReader("x"))
	post.Header.Set("Authorization", "Bearer "+graphTok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, post)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("graph send %d %s", rec.Code, rec.Body.String())
	}

	root, _ := http.NewRequest(http.MethodPost, "/servicebus/ns1/queues/q1/messages", strings.NewReader("ok"))
	root.Header.Set("Authorization", "Bearer root-tok")
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, root)
	if rrec.Code != http.StatusCreated {
		t.Fatalf("root send %d %s", rrec.Code, rrec.Body.String())
	}
}
