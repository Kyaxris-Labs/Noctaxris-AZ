package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestInstanceDiscoveryAnonymous(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{
		Store:      st,
		TenantID:   config.DefaultTenantID,
		PublicBase: "https://127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	path := "/common/discovery/instance?api-version=1.1&authorization_endpoint=https://127.0.0.1:4599/" +
		config.DefaultTenantID + "/oauth2/v2.0/authorize"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	if !authn.IsPublicPath("/common/discovery/instance") {
		t.Fatal("instance discovery must be public")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	td, _ := body["tenant_discovery_endpoint"].(string)
	want := "https://127.0.0.1:4599/" + config.DefaultTenantID + "/v2.0/.well-known/openid-configuration"
	if td != want {
		t.Fatalf("tenant_discovery_endpoint=%q want %q", td, want)
	}
}
