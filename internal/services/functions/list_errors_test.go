package functions_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestFunctionAppListNotFoundAndUnauth(t *testing.T) {
	mux := mountFunctions(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites"

	req := httptest.NewRequest(http.MethodPut, base+"/fn-list",
		bytes.NewReader([]byte(`{"location":"eastus","properties":{"labMockResponse":"plain"}}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	var list map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list["value"].([]any)) < 1 {
		t.Fatalf("list %#v", list)
	}

	req = httptest.NewRequest(http.MethodGet, base+"/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, base+"/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/functions/missing/invoke", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invoke missing %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/functions/fn-list/invoke", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke plain %d %s", rec.Code, rec.Body.String())
	}
	var plain map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	if plain["result"] != "plain" {
		t.Fatalf("plain invoke %#v", plain)
	}

	unauth := mountFunctions(t, func(*http.Request) (authn.Principal, bool) { return authn.Principal{}, false })
	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	unauth.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", rec.Code)
	}

	badAud := mountFunctions(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "x", IsRoot: false, Audiences: []string{"https://graph.microsoft.com"}}, true
	})
	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	badAud.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("bad audience %d %s", rec.Code, rec.Body.String())
	}
}
