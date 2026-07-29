package table_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestTableEntityInsertQueryGet(t *testing.T) {
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

	putTable, err := http.NewRequest(http.MethodPut, srv.URL+"/table/acct1/people", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(putTable, "acct1", key)
	res, err := http.DefaultClient.Do(putTable)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create table status %d: %s", res.StatusCode, body)
	}

	insert, err := http.NewRequest(http.MethodPost, srv.URL+"/table/acct1/people",
		strings.NewReader(`{"PartitionKey":"p1","RowKey":"r1","Name":"Ada"}`))
	if err != nil {
		t.Fatal(err)
	}
	insert.Header.Set("Content-Type", "application/json")
	signSharedKey(insert, "acct1", key)
	ires, err := http.DefaultClient.Do(insert)
	if err != nil {
		t.Fatal(err)
	}
	defer ires.Body.Close()
	if ires.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(ires.Body)
		t.Fatalf("insert status %d: %s", ires.StatusCode, body)
	}

	get, err := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1/people/p1/r1", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(get, "acct1", key)
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(gres.Body)
		t.Fatalf("get status %d: %s", gres.StatusCode, body)
	}
	var row map[string]any
	if err := json.NewDecoder(gres.Body).Decode(&row); err != nil {
		t.Fatal(err)
	}
	if row["Name"] != "Ada" {
		t.Fatalf("got %#v", row)
	}

	q, err := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1/people?$filter=PartitionKey%20eq%20'p1'&$top=10", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(q, "acct1", key)
	qres, err := http.DefaultClient.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	if qres.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(qres.Body)
		t.Fatalf("query status %d: %s", qres.StatusCode, body)
	}
	var list struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.NewDecoder(qres.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Value) != 1 {
		t.Fatalf("want 1 entity, got %d", len(list.Value))
	}

	del, err := http.NewRequest(http.MethodDelete, srv.URL+"/table/acct1/people/p1/r1", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(del, "acct1", key)
	dres, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer dres.Body.Close()
	if dres.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(dres.Body)
		t.Fatalf("delete entity status %d: %s", dres.StatusCode, body)
	}

	listTables, err := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(listTables, "acct1", key)
	ltres, err := http.DefaultClient.Do(listTables)
	if err != nil {
		t.Fatal(err)
	}
	defer ltres.Body.Close()
	var tables struct {
		Value []map[string]string `json:"value"`
	}
	if err := json.NewDecoder(ltres.Body).Decode(&tables); err != nil {
		t.Fatal(err)
	}
	if len(tables.Value) != 1 || tables.Value[0]["TableName"] != "people" {
		t.Fatalf("list tables %#v", tables)
	}

	delTable, err := http.NewRequest(http.MethodDelete, srv.URL+"/table/acct1/people", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(delTable, "acct1", key)
	dtres, err := http.DefaultClient.Do(delTable)
	if err != nil {
		t.Fatal(err)
	}
	defer dtres.Body.Close()
	if dtres.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(dtres.Body)
		t.Fatalf("delete table status %d: %s", dtres.StatusCode, body)
	}
}

func signSharedKey(r *http.Request, account, accountKey string) {
	sts := authn.StorageStringToSign(r)
	raw, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		raw = []byte(accountKey)
	}
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	r.Header.Set("Authorization", "SharedKey "+account+":"+sig)
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 3)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
