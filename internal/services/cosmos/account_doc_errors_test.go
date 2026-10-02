package cosmos_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/cosmos"
)

func TestCosmosMissingAccountDocsAndKeyPaths(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &cosmos.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)

	arm := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/missing"
	get := httptest.NewRequest(http.MethodGet, arm, nil)
	get.Header.Set("Authorization", "Bearer tok")
	grec := httptest.NewRecorder()
	mux.ServeHTTP(grec, get)
	if grec.Code != http.StatusNotFound {
		t.Fatalf("missing get %d %s", grec.Code, grec.Body.String())
	}

	keys := httptest.NewRequest(http.MethodPost, arm+"/listKeys", nil)
	keys.Header.Set("Authorization", "Bearer tok")
	krec := httptest.NewRecorder()
	mux.ServeHTTP(krec, keys)
	if krec.Code != http.StatusNotFound {
		t.Fatalf("missing keys %d %s", krec.Code, krec.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cdb",
		strings.NewReader(`{}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	mux.ServeHTTP(prec, put)
	if prec.Code != http.StatusOK {
		t.Fatalf("put %d %s", prec.Code, prec.Body.String())
	}

	_, _, _, key, ok, err := st.GetCosmosAccountByName("cdb")
	if err != nil || !ok || key == "" {
		t.Fatal(err)
	}

	listOK := httptest.NewRequest(http.MethodPost,
		"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cdb/listKeys", nil)
	listOK.Header.Set("Authorization", "Bearer tok")
	lrec := httptest.NewRecorder()
	mux.ServeHTTP(lrec, listOK)
	if lrec.Code != http.StatusOK || !strings.Contains(lrec.Body.String(), "primaryMasterKey") {
		t.Fatalf("listKeys %d %s", lrec.Code, lrec.Body.String())
	}

	missDoc := httptest.NewRequest(http.MethodGet, "/cosmos/cdb/dbs/db1/colls/c1/docs/nope?pk=p1", nil)
	missDoc.Header.Set("x-ms-cosmos-account-key", key)
	md := httptest.NewRecorder()
	mux.ServeHTTP(md, missDoc)
	if md.Code != http.StatusNotFound {
		t.Fatalf("missing doc %d", md.Code)
	}

	noAcct := httptest.NewRequest(http.MethodPut, "/cosmos/ghost/dbs/db1", nil)
	noAcct.Header.Set("Authorization", "Bearer tok")
	narec := httptest.NewRecorder()
	mux.ServeHTTP(narec, noAcct)
	if narec.Code != http.StatusNotFound {
		t.Fatalf("ghost account %d %s", narec.Code, narec.Body.String())
	}

	wrongKeyGhost := httptest.NewRequest(http.MethodPut, "/cosmos/ghost/dbs/db1", nil)
	wrongKeyGhost.Header.Set("x-ms-cosmos-account-key", "wrong")
	wg := httptest.NewRecorder()
	mux.ServeHTTP(wg, wrongKeyGhost)
	if wg.Code != http.StatusUnauthorized {
		t.Fatalf("ghost key %d", wg.Code)
	}

	db := httptest.NewRequest(http.MethodPut, "/cosmos/cdb/dbs/db1", nil)
	db.Header.Set("x-ms-cosmos-account-key", key)
	dbrec := httptest.NewRecorder()
	mux.ServeHTTP(dbrec, db)
	if dbrec.Code != http.StatusOK {
		t.Fatalf("db %d", dbrec.Code)
	}
	coll := httptest.NewRequest(http.MethodPut, "/cosmos/cdb/dbs/db1/colls/c1", strings.NewReader(`{}`))
	coll.Header.Set("x-ms-cosmos-account-key", key)
	coll.Header.Set("Content-Type", "application/json")
	crec := httptest.NewRecorder()
	mux.ServeHTTP(crec, coll)
	if crec.Code != http.StatusOK {
		t.Fatalf("coll %d", crec.Code)
	}

	doc := httptest.NewRequest(http.MethodPut, "/cosmos/cdb/dbs/db1/colls/c1/docs/i1",
		strings.NewReader(`{"id":"i1","n":1}`))
	doc.Header.Set("x-ms-cosmos-account-key", key)
	doc.Header.Set("Content-Type", "application/json")
	drec := httptest.NewRecorder()
	mux.ServeHTTP(drec, doc)
	if drec.Code != http.StatusOK {
		b, _ := io.ReadAll(drec.Body)
		t.Fatalf("doc %d %s", drec.Code, b)
	}

	q := httptest.NewRequest(http.MethodGet, "/cosmos/cdb/dbs/db1/colls/c1/docs?id=i1", nil)
	q.Header.Set("x-ms-cosmos-account-key", key)
	qrec := httptest.NewRecorder()
	mux.ServeHTTP(qrec, q)
	if qrec.Code != http.StatusOK || !strings.Contains(qrec.Body.String(), "i1") {
		t.Fatalf("query by id %d %s", qrec.Code, qrec.Body.String())
	}

	if err := st.UpsertCosmosItem("cdb", "db1", "c1", "raw1", "raw1", "not-json"); err != nil {
		t.Fatal(err)
	}
	cf := httptest.NewRequest(http.MethodGet, "/cosmos/cdb/dbs/db1/colls/c1/changefeed", nil)
	cf.Header.Set("x-ms-cosmos-account-key", key)
	cfrec := httptest.NewRecorder()
	mux.ServeHTTP(cfrec, cf)
	if cfrec.Code != http.StatusOK || !strings.Contains(cfrec.Body.String(), `"raw"`) {
		t.Fatalf("changefeed raw wrap %d %s", cfrec.Code, cfrec.Body.String())
	}
}
