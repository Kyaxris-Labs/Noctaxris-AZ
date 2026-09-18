package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestEntraApplicationsCRUD(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(wrap)
	defer srv.Close()
	create, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1.0/applications",
		strings.NewReader(`{"displayName":"demo"}`))
	create.Header.Set("Content-Type", "application/json")
	cr, err := http.DefaultClient.Do(create)
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Body.Close()
	if cr.StatusCode != http.StatusCreated {
		t.Fatalf("create %d", cr.StatusCode)
	}
	var created map[string]any
	_ = json.NewDecoder(cr.Body).Decode(&created)
	appID, _ := created["appId"].(string)
	appObj, _ := created["id"].(string)
	if appID == "" || appObj == "" {
		t.Fatal(created)
	}

	list, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1.0/applications", nil)
	lr, _ := http.DefaultClient.Do(list)
	lr.Body.Close()
	if lr.StatusCode != http.StatusOK {
		t.Fatalf("list %d", lr.StatusCode)
	}
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1.0/applications/"+appID, nil)
	gr, _ := http.DefaultClient.Do(get)
	gr.Body.Close()
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("get %d", gr.StatusCode)
	}
	patch, _ := http.NewRequest(http.MethodPatch, srv.URL+"/v1.0/applications/"+appID,
		strings.NewReader(`{"displayName":"renamed"}`))
	patch.Header.Set("Content-Type", "application/json")
	pr, _ := http.DefaultClient.Do(patch)
	pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("patch %d", pr.StatusCode)
	}
	delClient, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1.0/applications/"+appID, nil)
	dcr, _ := http.DefaultClient.Do(delClient)
	dcr.Body.Close()
	if dcr.StatusCode != http.StatusNotFound {
		t.Fatalf("delete by appId %d", dcr.StatusCode)
	}
	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1.0/applications/"+appObj, nil)
	dr, _ := http.DefaultClient.Do(del)
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", dr.StatusCode)
	}

	bare := http.NewServeMux()
	svc.Mount(bare)
	rec := httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.0/applications", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", rec.Code)
	}
}
