package servicebus_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/servicebus"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestServiceBusQueueMessageHTTPAndStore(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "ns1", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusQueue("ns1", "q1"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSB("ns1", "q1", []byte("from-store")); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.DequeueSB("ns1", "q1")
	if err != nil || !ok || string(body) != "from-store" {
		t.Fatalf("store dequeue: ok=%v body=%q err=%v", ok, body, err)
	}

	h := &servicebus.Handler{
		Store:          st,
		Auth:           &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		AMQPListenAddr: "127.0.0.1:5672",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	postReq, err := http.NewRequest(http.MethodPost, srv.URL+"/servicebus/ns1/queues/q1/messages",
		strings.NewReader("http-msg"))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Header.Set("Authorization", "Bearer root-token")
	postRes, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	defer postRes.Body.Close()
	if postRes.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(postRes.Body)
		t.Fatalf("post status %d: %s", postRes.StatusCode, b)
	}

	getReq, err := http.NewRequest(http.MethodGet, srv.URL+"/servicebus/ns1/queues/q1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	getReq.Header.Set("Authorization", "Bearer root-token")
	getRes, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getRes.Body.Close()
	if getRes.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getRes.Body)
		t.Fatalf("get status %d: %s", getRes.StatusCode, b)
	}
	got, _ := io.ReadAll(getRes.Body)
	if string(got) != "http-msg" {
		t.Fatalf("got %q", got)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 7)
	}
	st, err := store.Open(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
