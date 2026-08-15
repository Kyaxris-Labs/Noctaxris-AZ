package appconfig_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppConfigFeatureFlagsAndSnapshots(t *testing.T) {
	mux := mountAppConfig(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg2"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put store %d %s", rec.Code, rec.Body.String())
	}

	ff := `{"enabled":true,"conditions":{"client_filters":[]}}`
	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg2/featureflags/beta", bytes.NewReader([]byte(ff)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put ff %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg2/featureflags/beta", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get ff %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg2/featureflags", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list ff %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg2/snapshots/snap1", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put snap %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg2/snapshots/snap1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get snap %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg2/featureflags/missing", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing ff %d", rec.Code)
	}
}
