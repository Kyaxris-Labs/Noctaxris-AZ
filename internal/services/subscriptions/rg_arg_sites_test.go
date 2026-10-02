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
)

func TestResourceGroupCRUDSitesAndARGFilters(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	svc := &subscriptions.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: sub,
		TenantID:       config.DefaultTenantID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)

	put := httptest.NewRequest(http.MethodPut, "/subscriptions/"+sub+"/resourceGroups/rg-cov?api-version=2022-12-01",
		strings.NewReader(`{"location":"westeurope"}`))
	put.Header.Set("Authorization", "Bearer "+rootToken)
	put.Header.Set("Content-Type", "application/json")
	put.RemoteAddr = "203.0.113.10:51515"
	prec := httptest.NewRecorder()
	h.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK && prec.Code != http.StatusCreated {
		t.Fatalf("put rg %d %s", prec.Code, prec.Body.String())
	}

	get := armGET(t, h, "/subscriptions/"+sub+"/resourcegroups/rg-cov?api-version=2022-12-01")
	if get.Code != http.StatusOK {
		t.Fatalf("get rg %d %s", get.Code, get.Body.String())
	}
	miss := armGET(t, h, "/subscriptions/"+sub+"/resourceGroups/no-such-rg?api-version=2022-12-01")
	if miss.Code != http.StatusNotFound {
		t.Fatalf("missing rg %d", miss.Code)
	}

	if err := st.UpsertProviderResource("Microsoft.Web/sites", sub, "rg-cov", "web-app", "eastus", `{}`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFunctionApp(sub, "rg-cov", "fn-cov", "eastus", "ok"); err != nil {
		t.Fatal(err)
	}
	sites := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Web/sites?api-version=2022-12-01")
	if sites.Code != http.StatusOK {
		t.Fatalf("sites %d %s", sites.Code, sites.Body.String())
	}
	var siteBody map[string]any
	_ = json.Unmarshal(sites.Body.Bytes(), &siteBody)
	vals, _ := siteBody["value"].([]any)
	foundApp, foundFn := false, false
	for _, raw := range vals {
		m, _ := raw.(map[string]any)
		switch m["name"] {
		case "web-app":
			foundApp = m["kind"] == "app"
		case "fn-cov":
			foundFn = m["kind"] == "functionapp"
		}
	}
	if !foundApp || !foundFn {
		t.Fatalf("sites missing kinds %#v", siteBody)
	}

	if _, err := st.UpsertStorageAccount(sub, "rg-cov", "sacov1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("sacov1", "logs"); err != nil {
		t.Fatal(err)
	}
	storage := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Storage/storageAccounts?api-version=2022-12-01")
	if storage.Code != http.StatusOK || !strings.Contains(storage.Body.String(), "containerCount") {
		t.Fatalf("storage props %d %s", storage.Code, storage.Body.String())
	}

	if err := st.UpsertARGResource("/subscriptions/"+sub+"/resourceGroups/rg-cov/providers/Microsoft.Storage/storageAccounts/sacov1",
		"Resources", "microsoft.storage/storageaccounts", "sacov1", sub, "rg-cov", config.DefaultTenantID, `{}`); err != nil {
		t.Fatal(err)
	}
	argReq := httptest.NewRequest(http.MethodPost, "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
		strings.NewReader(`{"subscriptions":["`+sub+`",""],`+
			`"query":"Resources | where type == 'microsoft.storage/storageaccounts' | limit 1"}`))
	argReq.Header.Set("Authorization", "Bearer "+rootToken)
	argReq.Header.Set("Content-Type", "application/json")
	argRec := httptest.NewRecorder()
	h.ServeHTTP(argRec, argReq)
	if argRec.Code != http.StatusOK {
		t.Fatalf("arg %d %s", argRec.Code, argRec.Body.String())
	}
	var argBody map[string]any
	_ = json.Unmarshal(argRec.Body.Bytes(), &argBody)
	data, _ := argBody["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("expected limit 1, got %#v", argBody)
	}

	badJSON := httptest.NewRequest(http.MethodPost, "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
		strings.NewReader(`{`))
	badJSON.Header.Set("Authorization", "Bearer "+rootToken)
	badJSON.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badJSON)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad arg json %d", badRec.Code)
	}

	empty := armGET(t, h, "/subscriptions/"+sub+"/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2022-12-01")
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"value":[]`) && !strings.Contains(empty.Body.String(), `"value": []`) {
		t.Fatalf("empty provider %d %s", empty.Code, empty.Body.String())
	}
}
