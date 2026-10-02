package cosmos_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/cosmos"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestCosmosDataPlaneRejectsGraphAndReaderOmitsKey(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &cosmos.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-tok", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	arm := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cdb"
	put, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer root-tok")
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK {
		t.Fatalf("put %d %s", prec.Code, prec.Body.String())
	}
	if strings.Contains(prec.Body.String(), "primaryMasterKey") {
		t.Fatalf("PUT must omit primaryMasterKey: %s", prec.Body.String())
	}

	get, _ := http.NewRequest(http.MethodGet, arm, nil)
	get.Header.Set("Authorization", "Bearer root-tok")
	grec := httptest.NewRecorder()
	mux.ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("get %d", grec.Code)
	}
	if strings.Contains(grec.Body.String(), "primaryMasterKey") {
		t.Fatalf("GET must omit primaryMasterKey: %s", grec.Body.String())
	}

	rootKeys, _ := http.NewRequest(http.MethodPost, arm+"/listKeys", nil)
	rootKeys.Header.Set("Authorization", "Bearer root-tok")
	rkrec := httptest.NewRecorder()
	mux.ServeHTTP(rkrec, rootKeys)
	if rkrec.Code != http.StatusOK || !strings.Contains(rkrec.Body.String(), "primaryMasterKey") {
		t.Fatalf("listKeys must return primaryMasterKey: %d %s", rkrec.Code, rkrec.Body.String())
	}

	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-reader", Scope: "/subscriptions/sub/resourceGroups/rg",
		RoleDefinitionID: authz.RoleReader, PrincipalID: "sp-reader", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	readerTok, _, err := es.MintAccessToken("sp-reader", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := http.NewRequest(http.MethodPost, arm+"/listKeys", nil)
	keys.Header.Set("Authorization", "Bearer "+readerTok)
	krec := httptest.NewRecorder()
	mux.ServeHTTP(krec, keys)
	if krec.Code != http.StatusForbidden {
		t.Fatalf("reader listKeys %d %s", krec.Code, krec.Body.String())
	}

	graphTok, _, err := es.MintAccessToken("sp-reader", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := http.NewRequest(http.MethodPut, "/cosmos/cdb/dbs/db1/colls/c1/docs/i1",
		strings.NewReader(`{"id":"i1"}`))
	doc.Header.Set("Authorization", "Bearer "+graphTok)
	doc.Header.Set("Content-Type", "application/json")
	drec := httptest.NewRecorder()
	mux.ServeHTTP(drec, doc)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("graph doc put %d %s", drec.Code, drec.Body.String())
	}
	var env map[string]any
	_ = json.Unmarshal(drec.Body.Bytes(), &env)
	errObj, _ := env["error"].(map[string]any)
	if errObj["code"] != "InvalidAuthenticationTokenAudience" {
		t.Fatalf("error %#v", env)
	}

	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-cosmos", Scope: "/subscriptions/sub/resourceGroups/rg",
		RoleDefinitionID: authz.RoleCosmosDataContributor, PrincipalID: "sp-data", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	dataTok, _, err := es.MintAccessToken("sp-data", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := http.NewRequest(http.MethodPut, "/cosmos/cdb/dbs/db1", nil)
	db.Header.Set("Authorization", "Bearer "+dataTok)
	dbrec := httptest.NewRecorder()
	mux.ServeHTTP(dbrec, db)
	if dbrec.Code != http.StatusOK {
		b, _ := io.ReadAll(dbrec.Body)
		t.Fatalf("data contributor put db %d %s", dbrec.Code, b)
	}
}
