package table_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/table"
)

func TestTableAuthorizeErrorsDeleteAndFilters(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	key, err := st.UpsertStorageAccount("sub", "rg", "acct1", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: "tid", PublicBase: "http://127.0.0.1:4599"}
	h := &table.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz: &authz.Evaluator{Assignments: st},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	putTable, _ := http.NewRequest(http.MethodPut, srv.URL+"/table/acct1/items", nil)
	signSharedKey(putTable, "acct1", key)
	pr, _ := http.DefaultClient.Do(putTable)
	pr.Body.Close()
	if pr.StatusCode != http.StatusCreated {
		t.Fatalf("create table %d", pr.StatusCode)
	}

	insert, _ := http.NewRequest(http.MethodPost, srv.URL+"/table/acct1/items",
		strings.NewReader(`{"PartitionKey":"p1","RowKey":"r1","Color":"red"}`))
	insert.Header.Set("Content-Type", "application/json")
	signSharedKey(insert, "acct1", key)
	ir, _ := http.DefaultClient.Do(insert)
	ir.Body.Close()
	if ir.StatusCode != http.StatusCreated {
		t.Fatalf("insert %d", ir.StatusCode)
	}

	// Auth failures.
	noAuth, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	nar, _ := http.DefaultClient.Do(noAuth)
	nar.Body.Close()
	if nar.StatusCode != http.StatusUnauthorized && nar.StatusCode != http.StatusForbidden {
		t.Fatalf("no auth %d", nar.StatusCode)
	}

	mismatch, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	signSharedKey(mismatch, "other", key)
	mmr, _ := http.DefaultClient.Do(mismatch)
	mmr.Body.Close()
	if mmr.StatusCode != http.StatusForbidden {
		t.Fatalf("account mismatch %d", mmr.StatusCode)
	}

	unknown, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/missing", nil)
	signSharedKey(unknown, "missing", key)
	uar, _ := http.DefaultClient.Do(unknown)
	uar.Body.Close()
	if uar.StatusCode != http.StatusNotFound && uar.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown account %d", uar.StatusCode)
	}

	badSig, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	badSig.Header.Set("Authorization", "SharedKey acct1:AAAA")
	badSig.Header.Set("x-ms-date", "Thu, 01 Jan 1970 00:00:00 GMT")
	bsr, _ := http.DefaultClient.Do(badSig)
	bsr.Body.Close()
	if bsr.StatusCode != http.StatusForbidden {
		t.Fatalf("bad sig %d", bsr.StatusCode)
	}

	// Root bearer data-plane.
	rootList, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	rootList.Header.Set("Authorization", "Bearer root-token")
	rlr, _ := http.DefaultClient.Do(rootList)
	rlr.Body.Close()
	if rlr.StatusCode != http.StatusOK {
		t.Fatalf("root list %d", rlr.StatusCode)
	}

	missingAcctBearer, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/nope", nil)
	missingAcctBearer.Header.Set("Authorization", "Bearer root-token")
	mabr, _ := http.DefaultClient.Do(missingAcctBearer)
	mabr.Body.Close()
	if mabr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing account bearer %d", mabr.StatusCode)
	}

	// Filter + top validation.
	q, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1/items?$filter=PartitionKey%20eq%20'p1'%20and%20Color%20eq%20'red'&$top=10", nil)
	signSharedKey(q, "acct1", key)
	qr, _ := http.DefaultClient.Do(q)
	body, _ := io.ReadAll(qr.Body)
	qr.Body.Close()
	if qr.StatusCode != http.StatusOK {
		t.Fatalf("query %d %s", qr.StatusCode, body)
	}
	badTop, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1/items?$top=-1", nil)
	signSharedKey(badTop, "acct1", key)
	btr, _ := http.DefaultClient.Do(badTop)
	btr.Body.Close()
	if btr.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad top %d", btr.StatusCode)
	}

	// Delete entity + missing delete.
	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/table/acct1/items/p1/r1", nil)
	signSharedKey(del, "acct1", key)
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete entity %d", dr.StatusCode)
	}
	del2, _ := http.NewRequest(http.MethodDelete, srv.URL+"/table/acct1/items/p1/r1", nil)
	signSharedKey(del2, "acct1", key)
	dr2, _ := http.DefaultClient.Do(del2)
	dr2.Body.Close()
	if dr2.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing entity %d", dr2.StatusCode)
	}

	delTable, _ := http.NewRequest(http.MethodDelete, srv.URL+"/table/acct1/items", nil)
	signSharedKey(delTable, "acct1", key)
	dtr, _ := http.DefaultClient.Do(delTable)
	dtr.Body.Close()
	if dtr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete table %d", dtr.StatusCode)
	}

	graphTok, _, err := es.MintAccessToken("nobody", authn.AudienceGraph)
	if err != nil {
		t.Fatal(err)
	}
	badAud, _ := http.NewRequest(http.MethodGet, srv.URL+"/table/acct1", nil)
	badAud.Header.Set("Authorization", "Bearer "+graphTok)
	bar, _ := http.DefaultClient.Do(badAud)
	bar.Body.Close()
	if bar.StatusCode != http.StatusUnauthorized && bar.StatusCode != http.StatusForbidden {
		t.Fatalf("graph aud %d", bar.StatusCode)
	}
}
