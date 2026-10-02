package table_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
)

func TestTableEntityPutMergeAndConflict(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	key, err := st.UpsertStorageAccount("sub", "rg", "acct1", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	h := &table.Handler{Store: st, Auth: &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"}}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	putTable, _ := http.NewRequest(http.MethodPut, srv.URL+"/table/acct1/items", nil)
	signSharedKey(putTable, "acct1", key)
	res, err := http.DefaultClient.Do(putTable)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create table %d", res.StatusCode)
	}

	insert, _ := http.NewRequest(http.MethodPost, srv.URL+"/table/acct1/items",
		strings.NewReader(`{"PartitionKey":"p1","RowKey":"r1","Color":"red"}`))
	insert.Header.Set("Content-Type", "application/json")
	signSharedKey(insert, "acct1", key)
	ires, err := http.DefaultClient.Do(insert)
	if err != nil {
		t.Fatal(err)
	}
	ires.Body.Close()
	if ires.StatusCode != http.StatusCreated {
		t.Fatalf("insert %d", ires.StatusCode)
	}

	dup, _ := http.NewRequest(http.MethodPost, srv.URL+"/table/acct1/items",
		strings.NewReader(`{"PartitionKey":"p1","RowKey":"r1","Color":"blue"}`))
	dup.Header.Set("Content-Type", "application/json")
	signSharedKey(dup, "acct1", key)
	dres, err := http.DefaultClient.Do(dup)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(dres.Body)
	dres.Body.Close()
	if dres.StatusCode != http.StatusConflict {
		t.Fatalf("dup insert %d %s", dres.StatusCode, body)
	}

	put, _ := http.NewRequest(http.MethodPut, srv.URL+"/table/acct1/items/p1/r1",
		strings.NewReader(`{"Size":"L"}`))
	put.Header.Set("Content-Type", "application/json")
	signSharedKey(put, "acct1", key)
	pres, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	if pres.StatusCode != http.StatusNoContent {
		t.Fatalf("put %d", pres.StatusCode)
	}

	merge, _ := http.NewRequest("MERGE", srv.URL+"/table/acct1/items/p1/r1",
		strings.NewReader(`{"Color":"green"}`))
	merge.Header.Set("Content-Type", "application/json")
	signSharedKey(merge, "acct1", key)
	mres, err := http.DefaultClient.Do(merge)
	if err != nil {
		t.Fatal(err)
	}
	mres.Body.Close()
	if mres.StatusCode != http.StatusNoContent {
		t.Fatalf("merge %d", mres.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1/items/p1/r1", nil)
	signSharedKey(get, "acct1", key)
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(gres.Body)
		t.Fatalf("get %d %s", gres.StatusCode, b)
	}
}
