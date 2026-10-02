package subscriptions_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/subscriptions"
)

func TestListResourceGroupsResourcesProvidersAndInventory(t *testing.T) {
	st := openStore(t)
	sub := config.DefaultSubscriptionID
	if err := st.UpsertResourceGroup(sub, "rg-a", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertStorageAccount(sub, "rg-a", "sa1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertFunctionApp(sub, "rg-a", "fa1", "eastus", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProviderResource("Microsoft.ContainerRegistry/registries", sub, "rg-a", "acr1", "eastus", `{}`); err != nil {
		t.Fatal(err)
	}

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

	getOK := func(path string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+rootToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	rgs := getOK("/subscriptions/" + sub + "/resourceGroups?api-version=2022-12-01")
	if len(rgs["value"].([]any)) < 1 {
		t.Fatalf("rgs %#v", rgs)
	}
	resources := getOK("/subscriptions/" + sub + "/resources?api-version=2022-12-01")
	if len(resources["value"].([]any)) < 1 {
		t.Fatalf("resources %#v", resources)
	}
	providers := getOK("/subscriptions/" + sub + "/providers?api-version=2022-12-01")
	if len(providers["value"].([]any)) < 3 {
		t.Fatalf("providers %#v", providers)
	}
	storage := getOK("/subscriptions/" + sub + "/providers/Microsoft.Storage/storageAccounts?api-version=2022-12-01")
	if len(storage["value"].([]any)) < 1 {
		t.Fatalf("storage %#v", storage)
	}
	sites := getOK("/subscriptions/" + sub + "/providers/Microsoft.Web/sites?api-version=2022-12-01")
	if len(sites["value"].([]any)) < 1 {
		t.Fatalf("sites %#v", sites)
	}
	acr := getOK("/subscriptions/" + sub + "/providers/Microsoft.ContainerRegistry/registries?api-version=2022-12-01")
	if len(acr["value"].([]any)) < 1 {
		t.Fatalf("acr %#v", acr)
	}
	mgs := getOK("/providers/Microsoft.Management/managementGroups?api-version=2021-04-01")
	if len(mgs["value"].([]any)) < 1 {
		t.Fatalf("mgs %#v", mgs)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/subscriptions/"+sub+"/resourceGroups", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing api-version status=%d", rec.Code)
	}
}
