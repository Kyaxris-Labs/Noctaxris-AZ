package appconfig_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppConfigSnapshotCapturesKVAndLabelFilter(t *testing.T) {
	mux := mountAppConfig(t, nil)
	base := "/subscriptions/" + testSub + "/resourceGroups/" + testRG +
		"/providers/Microsoft.AppConfiguration/configurationStores/cfg-snap"
	req := httptest.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"location":"eastus"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put store %d %s", rec.Code, rec.Body.String())
	}

	putKV := func(key, label, value string) {
		t.Helper()
		body := `{"value":"` + value + `","label":"` + label + `"}`
		path := "/appconfig/cfg-snap/kv/" + key
		if label != "" {
			path += "?label=" + label
		}
		r := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("put kv %s %d %s", key, w.Code, w.Body.String())
		}
	}
	putKV("color", "", "blue")
	putKV("color", "prod", "navy")

	req = httptest.NewRequest(http.MethodPut, "/appconfig/cfg-snap/snapshots/freeze1", bytes.NewReader([]byte(`{}`)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put snap %d %s", rec.Code, rec.Body.String())
	}

	putKV("color", "", "red")

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-snap/snapshots/freeze1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get snap %d %s", rec.Code, rec.Body.String())
	}
	var snap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	items, _ := snap["items"].([]any)
	foundBlue := false
	foundRed := false
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["key"] == "color" && m["label"] == "" && m["value"] == "blue" {
			foundBlue = true
		}
		if m["value"] == "red" {
			foundRed = true
		}
	}
	if !foundBlue {
		t.Fatalf("snapshot lost captured value: %#v", snap)
	}
	if foundRed {
		t.Fatalf("snapshot followed live KV: %#v", snap)
	}

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-snap/snapshots", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list snap %d %s", rec.Code, rec.Body.String())
	}
	var listed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	listItems, _ := listed["items"].([]any)
	if len(listItems) != 1 {
		t.Fatalf("list snapshots %#v", listed)
	}

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-snap/snapshots/freeze1?label=prod", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("label filter %d %s", rec.Code, rec.Body.String())
	}
	var filtered map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &filtered)
	fitems, _ := filtered["items"].([]any)
	if len(fitems) != 1 {
		t.Fatalf("label filter items %#v", filtered)
	}
	fm, _ := fitems[0].(map[string]any)
	if fm["value"] != "navy" || fm["label"] != "prod" {
		t.Fatalf("label filter row %#v", fm)
	}

	req = httptest.NewRequest(http.MethodGet, "/appconfig/cfg-snap/kv?snapshot=freeze1&label=prod", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("kv snapshot %d %s", rec.Code, rec.Body.String())
	}
}
