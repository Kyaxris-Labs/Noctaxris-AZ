package frontdoor_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/frontdoor"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := dir + "/master.key"
	key, err := store.LoadOrCreateMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir+"/data", key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestARMPutGet(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &frontdoor.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cdn/profiles/demo"
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"eastus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("put %d: %s", res.StatusCode, b)
	}
	get, _ := http.NewRequest(http.MethodGet, url, nil)
	get.Header.Set("Authorization", "Bearer tok")
	gres, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gres.StatusCode)
	}
}
