package storage_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
)

func TestListBlobsJSONDefaultAndXMLWhenAsked(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	key, err := st.UpsertStorageAccount("sub", "rg", "acct1", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("acct1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob("acct1", "c1", "terraform.tfstate", []byte("{}"), "application/json"); err != nil {
		t.Fatal(err)
	}

	h := &storage.Handler{
		Store:      st,
		Auth:       &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token"},
		ListenAddr: "127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jsonReq, err := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1/c1", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(jsonReq, "acct1", key)
	jsonRes, err := http.DefaultClient.Do(jsonReq)
	if err != nil {
		t.Fatal(err)
	}
	defer jsonRes.Body.Close()
	body, _ := io.ReadAll(jsonRes.Body)
	if jsonRes.StatusCode != http.StatusOK || !strings.Contains(string(body), `"blobs"`) {
		t.Fatalf("json list status=%d body=%s", jsonRes.StatusCode, body)
	}

	xmlReq, err := http.NewRequest(http.MethodGet, srv.URL+"/blob/acct1/c1?restype=container&comp=list", nil)
	if err != nil {
		t.Fatal(err)
	}
	signSharedKey(xmlReq, "acct1", key)
	xmlRes, err := http.DefaultClient.Do(xmlReq)
	if err != nil {
		t.Fatal(err)
	}
	defer xmlRes.Body.Close()
	xmlBody, _ := io.ReadAll(xmlRes.Body)
	if xmlRes.StatusCode != http.StatusOK {
		t.Fatalf("xml list status=%d body=%s", xmlRes.StatusCode, xmlBody)
	}
	if !strings.Contains(string(xmlBody), "EnumerationResults") || !strings.Contains(string(xmlBody), "terraform.tfstate") {
		t.Fatalf("xml body=%s", xmlBody)
	}
}
