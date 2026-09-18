package subscriptions_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func mountARM(t *testing.T, st *store.Store) http.Handler {
	t.Helper()
	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	return withAuth(st, mux)
}

func armGET(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSubscriptionListTenantsARGAndProviderInventory(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	tid := config.DefaultTenantID
	if err := st.UpsertProviderResource("Microsoft.Compute/virtualMachines", sub, "rg1", "vm-lab", "eastus", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFunctionApp(sub, "rg1", "fn-lab", "eastus", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertARGResource("/subscriptions/"+sub+"/providers/Microsoft.Security/assessments/a1",
		"SecurityResources", "microsoft.security/assessments", "a1", sub, "rg1", tid, `{"status":"Unhealthy"}`); err != nil {
		t.Fatal(err)
	}

	h := mountARM(t, st)

	list := armGET(t, h, "/subscriptions?api-version=2022-12-01")
	if list.Code != http.StatusOK {
		t.Fatalf("list subscriptions %d body=%s", list.Code, list.Body.String())
	}
	var listBody map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &listBody); err != nil {
		t.Fatal(err)
	}
	vals, _ := listBody["value"].([]any)
	foundSub := false
	for _, raw := range vals {
		m, _ := raw.(map[string]any)
		if m["subscriptionId"] == sub {
			foundSub = true
		}
	}
	if !foundSub {
		t.Fatalf("seeded subscription missing %#v", listBody)
	}

	tenants := armGET(t, h, "/tenants?api-version=2022-12-01")
	if tenants.Code != http.StatusOK {
		t.Fatalf("tenants %d body=%s", tenants.Code, tenants.Body.String())
	}
	var tenantBody map[string]any
	if err := json.Unmarshal(tenants.Body.Bytes(), &tenantBody); err != nil {
		t.Fatal(err)
	}
	tvals, _ := tenantBody["value"].([]any)
	if len(tvals) == 0 {
		t.Fatalf("tenants empty %#v", tenantBody)
	}

	get := armGET(t, h, "/subscriptions/"+sub+"?api-version=2022-12-01")
	if get.Code != http.StatusOK {
		t.Fatalf("get subscription %d", get.Code)
	}

	missingVer := httptest.NewRequest(http.MethodGet, "/subscriptions/"+sub, nil)
	missingVer.Header.Set("Authorization", "Bearer "+rootToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, missingVer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing api-version %d", rec.Code)
	}

	vms := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01")
	if vms.Code != http.StatusOK {
		t.Fatalf("vms %d body=%s", vms.Code, vms.Body.String())
	}
	var vmBody map[string]any
	_ = json.Unmarshal(vms.Body.Bytes(), &vmBody)
	vmVals, _ := vmBody["value"].([]any)
	if len(vmVals) != 1 {
		t.Fatalf("expected vm from full ARM type key, got %#v", vmBody)
	}

	auto := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01")
	if auto.Code != http.StatusOK {
		t.Fatalf("automation %d body=%s", auto.Code, auto.Body.String())
	}
	var autoBody map[string]any
	_ = json.Unmarshal(auto.Body.Bytes(), &autoBody)
	av, ok := autoBody["value"].([]any)
	if !ok || len(av) != 0 {
		t.Fatalf("automation value %#v", autoBody["value"])
	}

	sites := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Web/sites?api-version=2023-12-01")
	if sites.Code != http.StatusOK {
		t.Fatalf("sites %d body=%s", sites.Code, sites.Body.String())
	}
	var siteBody map[string]any
	_ = json.Unmarshal(sites.Body.Bytes(), &siteBody)
	sv, _ := siteBody["value"].([]any)
	foundFn := false
	for _, raw := range sv {
		m, _ := raw.(map[string]any)
		if m["name"] == "fn-lab" && m["kind"] == "functionapp" && m["type"] == "Microsoft.Web/sites" {
			foundFn = true
		}
	}
	if !foundFn {
		t.Fatalf("function app missing from sites %#v", siteBody)
	}

	argReq := httptest.NewRequest(http.MethodPost, "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
		strings.NewReader(`{"subscriptions":["`+sub+`"],"query":"SecurityResources | where type == 'microsoft.security/assessments'"}`))
	argReq.Header.Set("Authorization", "Bearer "+rootToken)
	argReq.Header.Set("Content-Type", "application/json")
	argRec := httptest.NewRecorder()
	h.ServeHTTP(argRec, argReq)
	if argRec.Code != http.StatusOK {
		t.Fatalf("arg %d body=%s", argRec.Code, argRec.Body.String())
	}
	var argBody map[string]any
	if err := json.Unmarshal(argRec.Body.Bytes(), &argBody); err != nil {
		t.Fatal(err)
	}
	data, _ := argBody["data"].([]any)
	if len(data) == 0 {
		t.Fatalf("SecurityResources empty %#v", argBody)
	}
}
