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

func TestConditionalAccessListAndUserAgent(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	graph := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	body := `{
		"displayName":"ua-gate",
		"state":"enabled",
		"conditions":{
			"applications":{"includeApplications":["ca-client"]},
			"userAgents":{"include":["LabAgent/1.0"]}
		}
	}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1.0/identity/conditionalAccess/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	graph.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create CA %d body=%s", rec.Code, rec.Body.String())
	}

	list := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodGet, "/v1.0/identity/conditionalAccess/policies", nil)
	graph.ServeHTTP(list, lreq)
	if list.Code != http.StatusOK {
		t.Fatalf("list CA %d body=%s", list.Code, list.Body.String())
	}
	var listed map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	vals, _ := listed["value"].([]any)
	if len(vals) == 0 {
		t.Fatalf("expected policy in list %#v", listed)
	}

	okTok := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=client_credentials&client_id=ca-client&scope=https://graph.microsoft.com/.default"))
	okReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okReq.Header.Set("User-Agent", "LabAgent/1.0")
	mux.ServeHTTP(okTok, okReq)
	if okTok.Code != http.StatusOK {
		t.Fatalf("matching UA %d body=%s", okTok.Code, okTok.Body.String())
	}

	denied := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=client_credentials&client_id=ca-client&scope=https://graph.microsoft.com/.default"))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.Header.Set("User-Agent", "OtherAgent/9.9")
	mux.ServeHTTP(denied, badReq)
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("wrong UA %d body=%s", denied.Code, denied.Body.String())
	}
	if !strings.Contains(denied.Body.String(), "AADSTS53003") || !strings.Contains(denied.Body.String(), "BlockedByConditionalAccess") {
		t.Fatalf("expected CA deny envelope: %s", denied.Body.String())
	}

	unknown := httptest.NewRecorder()
	unkReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token",
		strings.NewReader("grant_type=client_credentials&client_id=other-client&scope=https://graph.microsoft.com/.default"))
	unkReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unkReq.Header.Set("User-Agent", "LabAgent/1.0")
	mux.ServeHTTP(unknown, unkReq)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "AADSTS53003") {
		t.Fatalf("unknown client %d body=%s", unknown.Code, unknown.Body.String())
	}
}
