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

func TestAADGraphUsersAndSOAPListUsers(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+config.DefaultTenantID+"/users?api-version=1.6", nil)
	wrap.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("aad users %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	val, _ := body["value"].([]any)
	if len(val) < 2 {
		t.Fatalf("aad users value %#v", body)
	}
	first, _ := val[0].(map[string]any)
	if first["objectId"] == nil || first["userPrincipalName"] == nil {
		t.Fatalf("aad user fields %#v", first)
	}

	missingVer := httptest.NewRecorder()
	wrap.ServeHTTP(missingVer, httptest.NewRequest(http.MethodGet, "/"+config.DefaultTenantID+"/users", nil))
	if missingVer.Code != http.StatusBadRequest {
		t.Fatalf("aad users without api-version %d", missingVer.Code)
	}

	commonUsers := httptest.NewRecorder()
	wrap.ServeHTTP(commonUsers, httptest.NewRequest(http.MethodGet, "/common/users?api-version=1.6", nil))
	if commonUsers.Code != http.StatusOK {
		t.Fatalf("common aad users %d", commonUsers.Code)
	}

	soap := httptest.NewRecorder()
	sreq := httptest.NewRequest(http.MethodPost, "/provisioningwebservice.svc",
		strings.NewReader(`<s:Envelope><s:Body><ListUsers xmlns="http://provisioning.microsoftonline.com/"/></s:Body></s:Envelope>`))
	sreq.Header.Set("Content-Type", "application/soap+xml")
	mux.ServeHTTP(soap, sreq)
	if soap.Code != http.StatusOK {
		t.Fatalf("soap %d body=%s", soap.Code, soap.Body.String())
	}
	out := soap.Body.String()
	if !strings.Contains(out, "ListUsersResponse") || !strings.Contains(out, "lab-admin@lab.local") {
		t.Fatalf("soap body %s", out)
	}

	iam := httptest.NewRecorder()
	wrap.ServeHTTP(iam, httptest.NewRequest(http.MethodGet, "/api/Users", nil))
	if iam.Code != http.StatusOK {
		t.Fatalf("iam portal %d body=%s", iam.Code, iam.Body.String())
	}
}
