package azuresql_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/azuresql"
)

func TestARMGetListOmitAdministratorLoginPassword(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &azuresql.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"location":"eastus","properties":{"administratorLogin":"sqladmin","administratorLoginPassword":"P@ssw0rd!","version":"12.0"}}`
	put, _ := http.NewRequest(http.MethodPut,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/demo",
		strings.NewReader(body))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK {
		t.Fatalf("put %d %s", prec.Code, prec.Body.String())
	}
	if strings.Contains(prec.Body.String(), "administratorLoginPassword") || strings.Contains(prec.Body.String(), "P@ssw0rd!") {
		t.Fatalf("PUT response must scrub password: %s", prec.Body.String())
	}

	get, _ := http.NewRequest(http.MethodGet,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/demo", nil)
	get.Header.Set("Authorization", "Bearer tok")
	grec := httptest.NewRecorder()
	mux.ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("get %d %s", grec.Code, grec.Body.String())
	}
	if strings.Contains(grec.Body.String(), "administratorLoginPassword") || strings.Contains(grec.Body.String(), "P@ssw0rd!") {
		t.Fatalf("GET must scrub password: %s", grec.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	props, _ := env["properties"].(map[string]any)
	if props["administratorLogin"] != "sqladmin" {
		t.Fatalf("non-secret login missing: %#v", props)
	}

	list, _ := http.NewRequest(http.MethodGet,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers", nil)
	list.Header.Set("Authorization", "Bearer tok")
	lrec := httptest.NewRecorder()
	mux.ServeHTTP(lrec, list)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list %d %s", lrec.Code, lrec.Body.String())
	}
	if strings.Contains(lrec.Body.String(), "administratorLoginPassword") || strings.Contains(lrec.Body.String(), "P@ssw0rd!") {
		t.Fatalf("list must scrub password: %s", lrec.Body.String())
	}
}
