package table_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
)

func TestTableMissingAccountIgnoresDefaultSubscriptionRole(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	keyA, err := st.UpsertStorageAccount("sub-a", "rg-a", "tablea", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := st.UpsertStorageAccount("sub-b", "rg-b", "tableb", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTable("tableb", "people"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.InsertEntity("tableb", "people", "pk", "rk", map[string]any{"Name": "table-secret-name"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-table-default", Scope: "/subscriptions/" + config.DefaultSubscriptionID,
		RoleDefinitionID: authz.RoleStorageTableDataReader,
		PrincipalID:      "sp-table-default", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &table.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	blobReaderTok, _, err := es.MintAccessToken("sp-table-default", authn.AudienceStorage)
	if err != nil {
		t.Fatal(err)
	}
	noneTok, _, err := es.MintAccessToken("sp-table-none", authn.AudienceStorage)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{blobReaderTok, noneTok} {
		req := httptest.NewRequest(http.MethodGet, "/table/no-such-acct/people/pk/rk", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusNotFound || strings.Contains(body, "table-secret-name") || strings.Contains(body, keyA) || strings.Contains(body, keyB) {
			t.Fatalf("missing table %d %s", rec.Code, body)
		}
	}

	cross := httptest.NewRequest(http.MethodGet, "/table/tableb/people/pk/rk", nil)
	signSharedKey(cross, "tablea", keyA)
	crossRec := httptest.NewRecorder()
	mux.ServeHTTP(crossRec, cross)
	if crossRec.Code != http.StatusForbidden || strings.Contains(crossRec.Body.String(), "table-secret-name") || strings.Contains(crossRec.Body.String(), keyB) {
		t.Fatalf("shared key cross account %d %s", crossRec.Code, crossRec.Body.String())
	}

	if _, err := st.UpsertStorageAccount("sub-c", "rg-c", "tablea", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	ambig := httptest.NewRequest(http.MethodGet, "/table/tablea", nil)
	ambig.Header.Set("Authorization", "Bearer root-token")
	ambigRec := httptest.NewRecorder()
	mux.ServeHTTP(ambigRec, ambig)
	if ambigRec.Code != http.StatusNotFound || strings.Contains(ambigRec.Body.String(), keyA) {
		t.Fatalf("ambiguous table %d %s", ambigRec.Code, ambigRec.Body.String())
	}
}
