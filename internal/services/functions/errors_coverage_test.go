package functions_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/functions"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestFunctionAppListNotFoundAudienceAndPlainMock(t *testing.T) {
	mux := mountFunctions(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites"

	req := httptest.NewRequest(http.MethodGet, base+"/missing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, base+"/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/functions/missing/invoke", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invoke missing %d", rec.Code)
	}

	body := `{"location":"eastus","properties":{"labMockResponse":"plain-text-result"}}`
	req = httptest.NewRequest(http.MethodPut, base+"/fn-plain", bytes.NewReader([]byte(body)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put plain %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("fn-plain")) {
		t.Fatalf("list body=%s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/functions/fn-plain/invoke", bytes.NewReader([]byte(`{"x":1}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke plain %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("plain-text-result")) {
		t.Fatalf("invoke body=%s", rec.Body.String())
	}

	// Empty mock falls back to {"ok":true}.
	req = httptest.NewRequest(http.MethodPut, base+"/fn-empty", bytes.NewReader([]byte(`{"location":"eastus","properties":{"labMockResponse":""}}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put empty %d", rec.Code)
	}
	// Default mock when empty string in put becomes {"ok":true} at store time.
	req = httptest.NewRequest(http.MethodPost, "/functions/fn-empty/invoke", bytes.NewReader(nil))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke empty %d %s", rec.Code, rec.Body.String())
	}
}

func TestFunctionAppWrapUnauthAndAudience(t *testing.T) {
	mux := mountFunctions(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{}, false
	})
	req := httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+testSub+"/resourceGroups/"+testRG+"/providers/Microsoft.Web/sites", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", rec.Code)
	}

	muxAud := mountFunctions(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "u", Audiences: []string{authn.AudienceGraph}}, true
	})
	rec = httptest.NewRecorder()
	muxAud.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("bad audience %d %s", rec.Code, rec.Body.String())
	}
}

func TestFunctionAppDefaultMockAndListAfterPut(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/secrets/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.EnsureRoot(testTenant, testSub, "root")
	_ = st.UpsertResourceGroup(testSub, testRG, "eastus")
	mux := http.NewServeMux()
	h := &functions.Handler{Store: st, Authz: &authz.Evaluator{Assignments: st}}
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG + "/providers/Microsoft.Web/sites/fn-def"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":""}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put default %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, base, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/functions/fn-def/invoke", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke %d %s", rec.Code, rec.Body.String())
	}
}
