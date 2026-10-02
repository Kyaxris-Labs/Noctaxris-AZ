package appconfig_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestAppConfigErrorsNotFoundAudienceAndListKV(t *testing.T) {
	mux := mountAppConfig(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores"

	req := httptest.NewRequest(http.MethodGet, base+"/missing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing store %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, base+"/cfg-err", bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, base+"/cfg-err", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg-err/kv/k1", bytes.NewReader([]byte(`{"value":"v1","label":"dev"}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put kv %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/kv/k1?label=dev", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get kv %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/kv", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list kv %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/kv/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing kv %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/appconfig/missing/featureflags/f1", bytes.NewReader([]byte(`{"enabled":true}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ff missing store %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg-err/featureflags/f1",
		bytes.NewReader([]byte(`{"enabled":true,"conditions":{"client_filters":[]}}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ff %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/featureflags/f1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get ff %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/featureflags/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing ff %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/featureflags", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list ff %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg-err/snapshots/s1", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put snap %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/snapshots/s1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get snap %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/snapshots/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing snap %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-err/snapshots", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list snap %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/appconfig/missing/snapshots/s1", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("snap missing store %d", rec.Code)
	}

	unauth := mountAppConfig(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{}, false
	})
	req = httptest.NewRequest(http.MethodGet, base+"/cfg-err", nil)
	rec = httptest.NewRecorder()
	unauth.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", rec.Code)
	}

	badAud := mountAppConfig(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "u", Audiences: []string{authn.AudienceGraph}}, true
	})
	req = httptest.NewRequest(http.MethodGet, base+"/cfg-err", nil)
	rec = httptest.NewRecorder()
	badAud.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("bad aud %d %s", rec.Code, rec.Body.String())
	}

	deny := mountAppConfig(t, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "nobody", Audiences: []string{authn.AudienceARM}}, true
	})
	req = httptest.NewRequest(http.MethodGet, base+"/cfg-err", nil)
	rec = httptest.NewRecorder()
	deny.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("deny %d %s", rec.Code, rec.Body.String())
	}
}
