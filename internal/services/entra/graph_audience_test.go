package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestGraphRejectsARMAndIssuerAudience(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	auth := &authn.Authenticator{Tokens: st, JWT: svc}

	armTok, _, err := svc.MintAccessToken("sp-lab-1", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	graphTok, _, err := svc.MintAccessToken("sp-lab-1", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	iss := "http://127.0.0.1:4599/" + config.DefaultTenantID + "/v2.0"
	issTok, _, err := svc.MintAccessToken("sp-lab-1", iss)
	if err != nil {
		t.Fatal(err)
	}

	call := func(tok string) *httptest.ResponseRecorder {
		t.Helper()
		p, err := auth.AuthenticateToken(tok)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1.0/users", nil)
		mux.ServeHTTP(rec, req.WithContext(authn.WithPrincipal(req.Context(), p)))
		return rec
	}

	if rec := call(armTok); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "InvalidAuthenticationToken") {
		t.Fatalf("ARM aud on Graph %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(issTok); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "InvalidAuthenticationToken") {
		t.Fatalf("issuer aud on Graph %d body=%s", rec.Code, rec.Body.String())
	}
	graph := call(graphTok)
	if graph.Code != http.StatusForbidden {
		t.Fatalf("Graph aud without directory role %d body=%s", graph.Code, graph.Body.String())
	}
	var denied map[string]any
	if err := json.Unmarshal(graph.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	errObj, _ := denied["error"].(map[string]any)
	if errObj["code"] != "Authorization_RequestDenied" {
		t.Fatalf("Graph audience passed the audience check and must fail the directory read, got %#v", denied)
	}
	if denied["value"] != nil || strings.Contains(graph.Body.String(), "lab-admin") {
		t.Fatalf("directory listed %#v", denied)
	}
}
