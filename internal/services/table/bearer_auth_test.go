package table_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
)

func TestTableBearerAuthAndMissingAccount(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if _, err := st.UpsertStorageAccount("sub", "rg", "acctb", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	h := &table.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	unauth, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acctb", nil)
	ur, _ := http.DefaultClient.Do(unauth)
	ur.Body.Close()
	if ur.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/missing-acct", nil)
	miss.Header.Set("Authorization", "Bearer root-token")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing account %d", mr.StatusCode)
	}

	put, _ := http.NewRequest(http.MethodPut, srv.URL+"/table/acctb/people", nil)
	put.Header.Set("Authorization", "Bearer root-token")
	pr, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(pr.Body)
	pr.Body.Close()
	if pr.StatusCode != http.StatusCreated {
		t.Fatalf("create table %d %s", pr.StatusCode, body)
	}

	ins, _ := http.NewRequest(http.MethodPost, srv.URL+"/table/acctb/people",
		strings.NewReader(`{"PartitionKey":"p","RowKey":"r","Name":"Ada"}`))
	ins.Header.Set("Authorization", "Bearer root-token")
	ins.Header.Set("Content-Type", "application/json")
	ir, _ := http.DefaultClient.Do(ins)
	ir.Body.Close()
	if ir.StatusCode != http.StatusCreated {
		t.Fatalf("insert %d", ir.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acctb/people/p/r", nil)
	get.Header.Set("Authorization", "Bearer root-token")
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gr.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/table/acctb/people/p/r", nil)
	del.Header.Set("Authorization", "Bearer root-token")
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", dr.StatusCode)
	}
}
