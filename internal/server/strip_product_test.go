package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestStripProductHealthPaths(t *testing.T) {
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
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()

	srv := New(config.Config{
		ListenAddr: "127.0.0.1:0", AMQPListenAddr: "127.0.0.1:0",
		RootClientID: "root", RootAccessToken: "tok",
		StripProduct: true,
	}, st, aud)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	for _, path := range []string{"/_lab/health", "/_lab/ready", "/_lab/version"} {
		res, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, res.StatusCode)
		}
		if path == "/_lab/version" {
			var got map[string]string
			if err := json.Unmarshal(body, &got); err != nil || got["version"] == "" {
				t.Fatalf("version body %q err=%v", body, err)
			}
		} else if string(body) != "ok" {
			t.Fatalf("%s body %q", path, body)
		}
	}
	for _, path := range []string{"/_noctaxris-az/health", "/_noctaxris-az/ready", "/_noctaxris-az/version"} {
		res, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("product path %s should 404, got %d", path, res.StatusCode)
		}
	}
}

func TestDefaultProductHealthPaths(t *testing.T) {
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
	aud, err := audit.NewWriter(dir + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer aud.Close()

	srv := New(config.Config{
		ListenAddr: "127.0.0.1:0", AMQPListenAddr: "127.0.0.1:0",
		RootClientID: "root", RootAccessToken: "tok",
	}, st, aud)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	for _, path := range []string{"/_noctaxris-az/health", "/_noctaxris-az/ready", "/_noctaxris-az/version"} {
		res, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, res.StatusCode)
		}
	}
	for _, path := range []string{"/_lab/health", "/_lab/ready", "/_lab/version"} {
		res, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("lab path %s should 404 when strip off, got %d", path, res.StatusCode)
		}
	}
}
