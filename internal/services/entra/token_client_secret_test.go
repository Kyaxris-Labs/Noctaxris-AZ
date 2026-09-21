package entra_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestClientCredentialsRequiresSecretOrAssertion(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	appID := "66666666-6666-6666-6666-666666666666"
	tokenPath := "/" + config.DefaultTenantID + "/oauth2/v2.0/token"

	missing := tokenPOST(t, mux, tokenPath, "grant_type=client_credentials&client_id="+appID+"&scope=https://graph.microsoft.com/.default")
	if missing.Code != 401 || !strings.Contains(missing.Body.String(), "invalid_client") {
		t.Fatalf("missing secret %d %s", missing.Code, missing.Body.String())
	}
	if !strings.Contains(missing.Body.String(), "AADSTS7000218") {
		t.Fatalf("expected AADSTS7000218: %s", missing.Body.String())
	}

	wrong := tokenPOST(t, mux, tokenPath, "grant_type=client_credentials&client_id="+appID+"&client_secret=not-the-secret&scope=https://graph.microsoft.com/.default")
	if wrong.Code != 401 || !strings.Contains(wrong.Body.String(), "invalid_client") {
		t.Fatalf("wrong secret %d %s", wrong.Code, wrong.Body.String())
	}
	if !strings.Contains(wrong.Body.String(), "AADSTS7000215") {
		t.Fatalf("expected AADSTS7000215: %s", wrong.Body.String())
	}

	secret := addClientSecret(t, st, config.DefaultTenantID, appID)
	ok := tokenPOST(t, mux, tokenPath, "grant_type=client_credentials&client_id="+appID+"&client_secret="+url.QueryEscape(secret)+"&scope=https://graph.microsoft.com/.default")
	if ok.Code != 200 {
		t.Fatalf("matching secret %d %s", ok.Code, ok.Body.String())
	}
}

func TestClientCredentialsUnknownClientWithoutSecret(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	rec := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		"grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("unknown client %d %s", rec.Code, rec.Body.String())
	}
}
