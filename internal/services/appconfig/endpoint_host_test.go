package appconfig_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppConfigEndpointFollowsRequestHost(t *testing.T) {
	mux := mountAppConfig(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg-host"

	put := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	put.Host = "203.0.113.10:59991"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	if got := endpointOf(t, rec.Body.Bytes()); got != "http://203.0.113.10:59991/appconfig/cfg-host" {
		t.Fatalf("put endpoint=%q", got)
	}

	get := httptest.NewRequest(http.MethodGet, base, nil)
	get.Host = "203.0.113.10:59991"
	get.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d %s", rec.Code, rec.Body.String())
	}
	if got := endpointOf(t, rec.Body.Bytes()); got != "https://203.0.113.10:59991/appconfig/cfg-host" {
		t.Fatalf("tls endpoint=%q", got)
	}

	plain := httptest.NewRequest(http.MethodGet, base, nil)
	plain.Host = ""
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, plain)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty host %d %s", rec.Code, rec.Body.String())
	}
	if got := endpointOf(t, rec.Body.Bytes()); got != "http://127.0.0.1:4599/appconfig/cfg-host" {
		t.Fatalf("empty host endpoint=%q", got)
	}
}

func TestAppConfigEndpointPublicURLOverridesHost(t *testing.T) {
	mux := mountAppConfigBase(t, nil, "https://lab.example:8443")
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg-pin"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	req.Host = "203.0.113.10:59991"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put %d %s", rec.Code, rec.Body.String())
	}
	if got := endpointOf(t, rec.Body.Bytes()); got != "https://lab.example:8443/appconfig/cfg-pin" {
		t.Fatalf("pinned endpoint=%q", got)
	}
}

func endpointOf(t *testing.T, body []byte) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	props, _ := doc["properties"].(map[string]any)
	ep, _ := props["endpoint"].(string)
	return ep
}
