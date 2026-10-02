package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestCosmosAccountKeySkipsBearerMiddleware(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(dir + "/master.key")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{
		ListenAddr:      "127.0.0.1:0",
		RootClientID:    "root",
		RootAccessToken: "tok",
		TenantID:        config.DefaultTenantID,
		SubscriptionID:  config.DefaultSubscriptionID,
	}
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()
	srv := New(cfg, st, aud)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	arm := hs.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cdb"
	put, _ := http.NewRequest(http.MethodPut, arm, strings.NewReader(`{"location":"eastus"}`))
	put.Header.Set("Authorization", "Bearer tok")
	put.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put account %d", res.StatusCode)
	}
	_, _, _, acctKey, ok, err := st.GetCosmosAccountByName("cdb")
	if err != nil || !ok || acctKey == "" {
		t.Fatal(err)
	}

	// Account-key alone must pass middleware and create a database.
	dbReq, _ := http.NewRequest(http.MethodPut, hs.URL+"/cosmos/cdb/dbs/db1", nil)
	dbReq.Header.Set("x-ms-cosmos-account-key", acctKey)
	dbRes, err := http.DefaultClient.Do(dbReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(dbRes.Body)
	dbRes.Body.Close()
	if dbRes.StatusCode != http.StatusOK {
		t.Fatalf("account-key putDB %d %s", dbRes.StatusCode, body)
	}

	bad, _ := http.NewRequest(http.MethodPut, hs.URL+"/cosmos/cdb/dbs/db2", nil)
	bad.Header.Set("x-ms-cosmos-account-key", "wrong")
	badRes, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	badRes.Body.Close()
	if badRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad key %d", badRes.StatusCode)
	}
}
