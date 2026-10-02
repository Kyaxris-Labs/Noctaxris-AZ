package authorization_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/authorization"
)

func TestRoleAssignmentListGetDeleteErrors(t *testing.T) {
	st := openStore(t)
	if err := st.UpsertResourceGroup(config.DefaultSubscriptionID, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}
	svc := &authorization.Service{
		Store:          st,
		Authz:          &authz.Evaluator{Assignments: st},
		PrincipalFrom:  authn.PrincipalFromContext,
		SubscriptionID: config.DefaultSubscriptionID,
	}
	mux := http.NewServeMux()
	svc.Mount(mux)
	h := withAuth(st, mux)
	sub := config.DefaultSubscriptionID

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleAssignments", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("list missing api-version status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth list status=%d", rec.Code)
	}

	putPath := "/subscriptions/" + sub + "/providers/Microsoft.Authorization/roleAssignments/ra-bad?api-version=2022-04-01"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, putPath, strings.NewReader(`{`))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid json status=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, putPath, strings.NewReader(`{"properties":{}}`))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fields status=%d", rec.Code)
	}

	body := `{"properties":{"roleDefinitionId":"` + authz.RoleReader + `","principalId":"sp-list-1"}}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleAssignments/ra-sub?api-version=2022-04-01",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put sub status=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyRG := `{"properties":{"roleDefinitionId":"` + authz.RoleContributor + `","principalId":"sp-list-2","principalType":"User"}}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut,
		"/subscriptions/"+sub+"/resourceGroups/rg-lab/providers/Microsoft.Authorization/roleAssignments/ra-rg?api-version=2022-04-01",
		strings.NewReader(bodyRG))
	req.Header.Set("Authorization", "Bearer "+rootToken)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put rg status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sub status=%d body=%s", rec.Code, rec.Body.String())
	}
	var list map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	vals, _ := list["value"].([]any)
	if len(vals) < 2 {
		t.Fatalf("list value %#v", list)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/resourceGroups/rg-lab/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rg status=%d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	vals, _ = list["value"].([]any)
	if len(vals) < 1 {
		t.Fatalf("rg list %#v", list)
	}

	getRG := "/subscriptions/" + sub + "/resourceGroups/rg-lab/providers/Microsoft.Authorization/roleAssignments/ra-rg?api-version=2022-04-01"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, getRG, nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get rg status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/resourceGroups/rg-lab/providers/Microsoft.Authorization/roleAssignments/missing?api-version=2022-04-01", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, getRG, nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete rg status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, getRG, nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete rg status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/subscriptions/"+sub+"/providers/Microsoft.Authorization/roleAssignments/missing?api-version=2022-04-01", nil)
	req.Header.Set("Authorization", "Bearer "+rootToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing sub status=%d", rec.Code)
	}
}
