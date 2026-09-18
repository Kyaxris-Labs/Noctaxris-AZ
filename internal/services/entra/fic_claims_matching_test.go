package entra_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestFederatedCredentialExactAndExpression(t *testing.T) {
	issuer := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	aud := "api://AzureADTokenExchange"

	t.Run("exact subject", func(t *testing.T) {
		st := openStore(t)
		svc, mux := newEntraMux(t, st)
		if _, err := st.CreateFIC(appObj, "exact", issuer, "repo:org/app", []string{aud}, ""); err != nil {
			t.Fatal(err)
		}
		assertWIF(t, svc, mux, appID, "repo:org/app", true)
		assertWIF(t, svc, mux, appID, "repo:org/other", false)
	})

	t.Run("over-broad matches", func(t *testing.T) {
		st := openStore(t)
		svc, mux := newEntraMux(t, st)
		expr := `{"value":"claims['sub'] matches 'repo:org/*'","languageVersion":1}`
		if _, err := st.CreateFIC(appObj, "broad", issuer, "", []string{aud}, expr); err != nil {
			t.Fatal(err)
		}
		assertWIF(t, svc, mux, appID, "repo:org/guessable", true)
	})

	t.Run("tight rejects", func(t *testing.T) {
		st := openStore(t)
		svc, mux := newEntraMux(t, st)
		expr := `{"value":"claims['sub'] eq 'repo:org/locked'","languageVersion":1}`
		if _, err := st.CreateFIC(appObj, "tight", issuer, "", []string{aud}, expr); err != nil {
			t.Fatal(err)
		}
		assertWIF(t, svc, mux, appID, "repo:org/locked", true)
		assertWIF(t, svc, mux, appID, "repo:org/wrong", false)
	})
}

func newEntraMux(t *testing.T, st *store.Store) (*entra.Service, *http.ServeMux) {
	t.Helper()
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	return svc, mux
}

func assertWIF(t *testing.T, svc *entra.Service, mux http.Handler, appID, sub string, wantOK bool) {
	t.Helper()
	assertion, err := svc.MintLabOIDCAssertion(sub, "api://AzureADTokenExchange")
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {appID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	}.Encode()
	rec := tokenPOST(t, mux, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", body)
	if wantOK && rec.Code != http.StatusOK {
		t.Fatalf("sub %q want OK got %d %s", sub, rec.Code, rec.Body.String())
	}
	if !wantOK && rec.Code == http.StatusOK {
		t.Fatalf("sub %q should be rejected: %s", sub, rec.Body.String())
	}
}
