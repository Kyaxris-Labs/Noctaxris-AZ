package servicebus_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/servicebus"
)

func TestServiceBusARMTopicsAndConnectionString(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &servicebus.Handler{
		Store:          st,
		Auth:           &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		AMQPListenAddr: "127.0.0.1:5672",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer root-token") }

	nsURL := srv.URL + "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns1"
	putNS, _ := http.NewRequest(http.MethodPut, nsURL, strings.NewReader(`{"location":"eastus"}`))
	auth(putNS)
	putNS.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(putNS)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("put ns %d: %s", res.StatusCode, b)
	}
	getNS, _ := http.NewRequest(http.MethodGet, nsURL, nil)
	auth(getNS)
	gn, _ := http.DefaultClient.Do(getNS)
	gn.Body.Close()
	if gn.StatusCode != http.StatusOK {
		t.Fatalf("get ns %d", gn.StatusCode)
	}

	qURL := nsURL + "/queues/q1"
	putQ, _ := http.NewRequest(http.MethodPut, qURL, strings.NewReader(`{}`))
	auth(putQ)
	putQ.Header.Set("Content-Type", "application/json")
	pq, _ := http.DefaultClient.Do(putQ)
	pq.Body.Close()
	if pq.StatusCode != http.StatusOK {
		t.Fatalf("put queue %d", pq.StatusCode)
	}
	getQ, _ := http.NewRequest(http.MethodGet, qURL, nil)
	auth(getQ)
	gq, _ := http.DefaultClient.Do(getQ)
	gq.Body.Close()
	if gq.StatusCode != http.StatusOK {
		t.Fatalf("get queue %d", gq.StatusCode)
	}

	cs, _ := http.NewRequest(http.MethodGet, nsURL+"/connectionString", nil)
	auth(cs)
	csr, err := http.DefaultClient.Do(cs)
	if err != nil {
		t.Fatal(err)
	}
	defer csr.Body.Close()
	if csr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(csr.Body)
		t.Fatalf("cs %d: %s", csr.StatusCode, b)
	}

	tURL := nsURL + "/topics/t1"
	putT, _ := http.NewRequest(http.MethodPut, tURL, strings.NewReader(`{}`))
	auth(putT)
	putT.Header.Set("Content-Type", "application/json")
	pt, _ := http.DefaultClient.Do(putT)
	pt.Body.Close()
	if pt.StatusCode != http.StatusOK {
		t.Fatalf("put topic %d", pt.StatusCode)
	}
	sURL := tURL + "/subscriptions/s1"
	putS, _ := http.NewRequest(http.MethodPut, sURL, strings.NewReader(`{}`))
	auth(putS)
	putS.Header.Set("Content-Type", "application/json")
	ps, _ := http.DefaultClient.Do(putS)
	ps.Body.Close()
	if ps.StatusCode != http.StatusOK {
		t.Fatalf("put sub %d", ps.StatusCode)
	}

	postTM, _ := http.NewRequest(http.MethodPost, srv.URL+"/servicebus/ns1/topics/t1/subscriptions/s1/messages",
		strings.NewReader("topic-msg"))
	auth(postTM)
	ptr, _ := http.DefaultClient.Do(postTM)
	ptr.Body.Close()
	if ptr.StatusCode != http.StatusCreated {
		t.Fatalf("post topic msg %d", ptr.StatusCode)
	}
	getTM, _ := http.NewRequest(http.MethodGet, srv.URL+"/servicebus/ns1/topics/t1/subscriptions/s1/messages", nil)
	auth(getTM)
	gtr, err := http.DefaultClient.Do(getTM)
	if err != nil {
		t.Fatal(err)
	}
	defer gtr.Body.Close()
	if gtr.StatusCode != http.StatusOK {
		t.Fatalf("get topic msg %d", gtr.StatusCode)
	}
	body, _ := io.ReadAll(gtr.Body)
	if string(body) != "topic-msg" {
		t.Fatalf("%q", body)
	}
	empty, _ := http.NewRequest(http.MethodGet, srv.URL+"/servicebus/ns1/topics/t1/subscriptions/s1/messages", nil)
	auth(empty)
	er, _ := http.DefaultClient.Do(empty)
	er.Body.Close()
	if er.StatusCode != http.StatusNoContent {
		t.Fatalf("empty %d", er.StatusCode)
	}

	miss, _ := http.NewRequest(http.MethodGet, srv.URL+"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/missing", nil)
	auth(miss)
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing ns %d", mr.StatusCode)
	}
}
