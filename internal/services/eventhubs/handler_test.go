package eventhubs_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/eventhubs"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEventHubsRoundtrip(t *testing.T) {
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
	h := &eventhubs.Handler{Store: st, Auth: &authn.Authenticator{RootClientID: "r", RootAccessToken: "tok"}}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1", strings.NewReader(`{"location":"eastus"}`))
	req.Header.Set("Authorization", "Bearer tok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
}
