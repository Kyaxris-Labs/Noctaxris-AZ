package nic_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/nic"
)

func TestARMListDeleteNotFoundUnauth(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	h := &nic.Handler{
		Store: st,
		Auth:  &authn.Authenticator{RootClientID: "root", RootAccessToken: "tok"},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := srv.URL + "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces"
	url := base + "/demo"
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(`{"location":"eastus","properties":{"x":1}}`))
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
	list, _ := http.NewRequest(http.MethodGet, base, nil)
	list.Header.Set("Authorization", "Bearer tok")
	lr, err := http.DefaultClient.Do(list)
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("list %d", lr.StatusCode)
	}
	miss, _ := http.NewRequest(http.MethodGet, base+"/missing", nil)
	miss.Header.Set("Authorization", "Bearer tok")
	mr, _ := http.DefaultClient.Do(miss)
	mr.Body.Close()
	if mr.StatusCode != http.StatusNotFound {
		t.Fatalf("missing %d", mr.StatusCode)
	}
	del, _ := http.NewRequest(http.MethodDelete, url, nil)
	del.Header.Set("Authorization", "Bearer tok")
	dr, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("delete %d", dr.StatusCode)
	}
	dr2, _ := http.DefaultClient.Do(del)
	dr2.Body.Close()
	if dr2.StatusCode != http.StatusNotFound {
		t.Fatalf("delete again %d", dr2.StatusCode)
	}
	unauth, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth %d", unauth.StatusCode)
	}
}
