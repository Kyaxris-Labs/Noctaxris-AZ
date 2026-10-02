package monitor_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/monitor"
)

func TestActivityInjectPositiveAndValidation(t *testing.T) {
	_, st := mountMonitor(t, nil)
	h := &monitor.Handler{
		Store: st, Authz: &authz.Evaluator{Assignments: st},
		ActivityInject: true, SubscriptionID: testSub, TenantID: testTenant,
	}
	mux := http.NewServeMux()
	h.Mount(mux, func(*http.Request) (authn.Principal, bool) {
		return authn.Principal{ID: "root", IsRoot: true}, true
	})

	body := `{
		"events":[{
			"eventTimestamp":"2021-05-06T07:08:09Z",
			"operationName":{"value":"Microsoft.Storage/storageAccounts/write"},
			"status":{"value":"Succeeded"},
			"caller":"alice",
			"callerIpAddress":"203.0.113.9",
			"resourceId":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1",
			"identity":{"claims":{"appid":"alice","token":"secret-token"},"nested":{"arr":[1,2,3]}}
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/activityLog:inject", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inject %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["written"] != float64(1) {
		t.Fatalf("written %#v", out)
	}
	rows, err := st.ListActivityLog(20)
	if err != nil || len(rows) == 0 {
		t.Fatalf("rows %v %v", rows, err)
	}
	found := false
	for _, row := range rows {
		if row["operation"] == "Microsoft.Storage/storageAccounts/write" {
			found = true
			if row["clientIp"] != "203.0.113.9" {
				t.Fatalf("ip %#v", row)
			}
			ident := row["identity"]
			if containsSecret(ident) {
				t.Fatalf("secret leaked in identity %q", ident)
			}
		}
	}
	if !found {
		t.Fatalf("missing injected op in %#v", rows)
	}

	single := `{"event":{"operationName":"Microsoft.KeyVault/vaults/read","status":"Failed","clientIp":"198.51.100.1"}}`
	req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/activityLog:inject", bytes.NewReader([]byte(single)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("single event %d %s", rec.Code, rec.Body.String())
	}

	for _, bad := range []string{
		`{`,
		`{}`,
		`{"events":[{"operationName":""}]}`,
		`{"events":[{"operationName":"x","eventTimestamp":"not-a-time"}]}`,
		`{"events":[{"operationName":"x","identity":"not-object"}]}`,
	} {
		req = httptest.NewRequest(http.MethodPost, "/_noctaxris-az/lab/activityLog:inject", bytes.NewReader([]byte(bad)))
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad %q status=%d body=%s", bad, rec.Code, rec.Body.String())
		}
	}
}

func containsSecret(s string) bool {
	return strings.Contains(s, "secret-token")
}
