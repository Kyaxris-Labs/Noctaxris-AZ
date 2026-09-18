package cosmos_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/cosmos"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCosmosAccountAndDocs(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &cosmos.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	arm := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cdb"
	req, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"westus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("put account %d: %s", res.StatusCode, b)
	}

	get, _ := http.NewRequest(http.MethodGet, arm, nil)
	get.Header.Set("Authorization", "Bearer tok")
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gres.StatusCode)
	}

	_, _, _, key, ok, err := st.GetCosmosAccountByName("cdb")
	if err != nil || !ok || key == "" {
		t.Fatal(err)
	}

	putDB, _ := http.NewRequest(http.MethodPut, srv.URL+"/cosmos/cdb/dbs/db1", nil)
	putDB.Header.Set("x-ms-cosmos-account-key", key)
	dbRes, err := http.DefaultClient.Do(putDB)
	if err != nil {
		t.Fatal(err)
	}
	defer dbRes.Body.Close()
	if dbRes.StatusCode != http.StatusOK {
		t.Fatalf("db %d", dbRes.StatusCode)
	}

	putColl, _ := http.NewRequest(http.MethodPut, srv.URL+"/cosmos/cdb/dbs/db1/colls/c1",
		strings.NewReader(`{"partitionKey":"/pk"}`))
	putColl.Header.Set("Authorization", "Bearer tok")
	putColl.Header.Set("Content-Type", "application/json")
	collRes, err := http.DefaultClient.Do(putColl)
	if err != nil {
		t.Fatal(err)
	}
	defer collRes.Body.Close()
	if collRes.StatusCode != http.StatusOK {
		t.Fatalf("coll %d", collRes.StatusCode)
	}

	putDoc, _ := http.NewRequest(http.MethodPut, srv.URL+"/cosmos/cdb/dbs/db1/colls/c1/docs/i1?pk=p1",
		strings.NewReader(`{"id":"i1","x":1}`))
	putDoc.Header.Set("Authorization", "Bearer tok")
	putDoc.Header.Set("Content-Type", "application/json")
	docRes, err := http.DefaultClient.Do(putDoc)
	if err != nil {
		t.Fatal(err)
	}
	defer docRes.Body.Close()
	if docRes.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(docRes.Body)
		t.Fatalf("doc %d: %s", docRes.StatusCode, b)
	}

	getDoc, _ := http.NewRequest(http.MethodGet, srv.URL+"/cosmos/cdb/dbs/db1/colls/c1/docs/i1?pk=p1", nil)
	getDoc.Header.Set("Authorization", "Bearer tok")
	gd, err := http.DefaultClient.Do(getDoc)
	if err != nil {
		t.Fatal(err)
	}
	defer gd.Body.Close()
	if gd.StatusCode != http.StatusOK {
		t.Fatalf("get doc %d", gd.StatusCode)
	}

	q, _ := http.NewRequest(http.MethodGet, srv.URL+"/cosmos/cdb/dbs/db1/colls/c1/docs?query=SELECT%20*%20FROM%20c%20WHERE%20c.id%20=%20'i1'", nil)
	q.Header.Set("Authorization", "Bearer tok")
	qr, err := http.DefaultClient.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	defer qr.Body.Close()
	if qr.StatusCode != http.StatusOK {
		t.Fatalf("query %d", qr.StatusCode)
	}

	cf, _ := http.NewRequest(http.MethodGet, srv.URL+"/cosmos/cdb/dbs/db1/colls/c1/changefeed", nil)
	cf.Header.Set("Authorization", "Bearer tok")
	cfr, err := http.DefaultClient.Do(cf)
	if err != nil {
		t.Fatal(err)
	}
	defer cfr.Body.Close()
	if cfr.StatusCode != http.StatusOK {
		t.Fatalf("changefeed %d", cfr.StatusCode)
	}
	cfBody, _ := io.ReadAll(cfr.Body)
	if !strings.Contains(string(cfBody), `"Documents"`) {
		t.Fatalf("changefeed body %s", cfBody)
	}

	bad, _ := http.NewRequest(http.MethodPut, srv.URL+"/cosmos/cdb/dbs/db2", nil)
	bad.Header.Set("x-ms-cosmos-account-key", "wrong")
	br, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Body.Close()
	if br.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad key %d", br.StatusCode)
	}

	unauth, err := http.Get(arm)
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", unauth.StatusCode)
	}
}
