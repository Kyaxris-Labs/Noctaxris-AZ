package subscriptions_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func TestSubscriptionListAndGetNilAuthorizerForbidsNonRoot(t *testing.T) {
	st := openStore(t)
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	userTok, _, err := es.MintAccessToken("user-no-role", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	auth := &authn.Authenticator{
		RootClientID:    "root",
		RootAccessToken: rootToken,
		Tokens:          st,
		JWT:             es,
	}
	svc := &subscriptions.Service{
		Store:          st,
		Auth:           auth,
		Authz:          nil,
		SubscriptionID: config.DefaultSubscriptionID,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)

	call := func(method, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	listDenied := call(http.MethodGet, "/subscriptions?api-version=2022-12-01", userTok)
	if listDenied.Code != http.StatusForbidden {
		t.Fatalf("nil authorizer list %d body=%s", listDenied.Code, listDenied.Body.String())
	}
	getDenied := call(http.MethodGet, "/subscriptions/"+config.DefaultSubscriptionID+"?api-version=2022-12-01", userTok)
	if getDenied.Code != http.StatusForbidden {
		t.Fatalf("nil authorizer get %d body=%s", getDenied.Code, getDenied.Body.String())
	}

	listRoot := call(http.MethodGet, "/subscriptions?api-version=2022-12-01", rootToken)
	if listRoot.Code != http.StatusOK {
		t.Fatalf("root list %d body=%s", listRoot.Code, listRoot.Body.String())
	}
	getRoot := call(http.MethodGet, "/subscriptions/"+config.DefaultSubscriptionID+"?api-version=2022-12-01", rootToken)
	if getRoot.Code != http.StatusOK {
		t.Fatalf("root get %d body=%s", getRoot.Code, getRoot.Body.String())
	}
}
