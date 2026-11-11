package storage_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/storage"
)

func TestListKeysScopeNameConflictAndMissingAccount(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}
	keyA, err := st.UpsertStorageAccount("sub-a", "rg-a", "owned", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := st.UpsertStorageAccount("sub-b", "rg-b", "owned", "eastus", "127.0.0.1:4599")
	if err != nil || keyB == keyA {
		t.Fatalf("other subscription key: %v", err)
	}
	if err := st.PutBlob("owned", "c1", "obj", []byte("owned-blob-bytes"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	otherKey, err := st.UpsertStorageAccount("sub-a", "rg-a", "other", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateContainer("other", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob("other", "c1", "obj", []byte("other-blob-bytes"), "text/plain"); err != nil {
		t.Fatal(err)
	}

	accountID := "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/owned"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-owner", Scope: accountID, RoleDefinitionID: authz.RoleOwner,
		PrincipalID: "sp-owner", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-reader", Scope: accountID, RoleDefinitionID: authz.RoleReader,
		PrincipalID: "sp-reader", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-blob-default", Scope: "/subscriptions/" + config.DefaultSubscriptionID,
		RoleDefinitionID: authz.RoleStorageBlobDataReader,
		PrincipalID:      "sp-blob-default", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}

	es := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	h := &storage.Handler{
		Store:      st,
		Auth:       &authn.Authenticator{RootClientID: "root", RootAccessToken: "root-token", Tokens: st, JWT: es},
		Authz:      &authz.Evaluator{Assignments: st},
		ListenAddr: "127.0.0.1:4599",
	}
	mux := http.NewServeMux()
	h.Register(mux)

	ownerTok, _, err := es.MintAccessToken("sp-owner", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	readerTok, _, err := es.MintAccessToken("sp-reader", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	blobTok, _, err := es.MintAccessToken("sp-blob-default", authn.AudienceStorage)
	if err != nil {
		t.Fatal(err)
	}
	noneTok, _, err := es.MintAccessToken("sp-none", authn.AudienceStorage)
	if err != nil {
		t.Fatal(err)
	}

	ownerKeys := serve(mux, http.MethodPost, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/owned/listKeys", ownerTok, "")
	if ownerKeys.Code != http.StatusOK || !strings.Contains(ownerKeys.Body.String(), keyA) || strings.Contains(ownerKeys.Body.String(), keyB) {
		t.Fatalf("owner listKeys %d %s", ownerKeys.Code, ownerKeys.Body.String())
	}
	readerKeys := serve(mux, http.MethodPost, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/owned/listKeys", readerTok, "")
	if readerKeys.Code != http.StatusForbidden || strings.Contains(readerKeys.Body.String(), keyA) || strings.Contains(readerKeys.Body.String(), keyB) {
		t.Fatalf("reader listKeys %d %s", readerKeys.Code, readerKeys.Body.String())
	}

	wrongRG := serve(mux, http.MethodPost, "/subscriptions/sub-a/resourceGroups/rg-wrong/providers/Microsoft.Storage/storageAccounts/owned/listKeys", "root-token", "")
	if wrongRG.Code != http.StatusNotFound || strings.Contains(wrongRG.Body.String(), keyA) || strings.Contains(wrongRG.Body.String(), keyB) {
		t.Fatalf("wrong rg listKeys %d %s", wrongRG.Code, wrongRG.Body.String())
	}
	otherSub := serve(mux, http.MethodPost, "/subscriptions/sub-c/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/owned/listKeys", "root-token", "")
	if otherSub.Code != http.StatusNotFound || strings.Contains(otherSub.Body.String(), keyA) || strings.Contains(otherSub.Body.String(), keyB) {
		t.Fatalf("other subscription listKeys %d %s", otherSub.Code, otherSub.Body.String())
	}
	missingName := serve(mux, http.MethodPost, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/missing/listKeys", "root-token", "")
	if missingName.Code != http.StatusNotFound || strings.Contains(missingName.Body.String(), keyA) || strings.Contains(missingName.Body.String(), otherKey) {
		t.Fatalf("missing listKeys %d %s", missingName.Code, missingName.Body.String())
	}
	scopedB := serve(mux, http.MethodPost, "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.Storage/storageAccounts/owned/listKeys", "root-token", "")
	if scopedB.Code != http.StatusOK || !strings.Contains(scopedB.Body.String(), keyB) || strings.Contains(scopedB.Body.String(), keyA) {
		t.Fatalf("sub-b listKeys %d %s", scopedB.Code, scopedB.Body.String())
	}

	again := serve(mux, http.MethodPut, "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/other", "root-token", `{"location":"westus"}`)
	if again.Code != http.StatusOK {
		t.Fatalf("update same account %d %s", again.Code, again.Body.String())
	}
	conflict := serve(mux, http.MethodPut, "/subscriptions/sub-c/resourceGroups/rg-c/providers/Microsoft.Storage/storageAccounts/owned", "root-token", `{"location":"eastus"}`)
	if conflict.Code != http.StatusConflict || strings.Contains(conflict.Body.String(), keyA) {
		t.Fatalf("duplicate name %d %s", conflict.Code, conflict.Body.String())
	}

	cross := httptest.NewRequest(http.MethodGet, "/blob/other/c1/obj", nil)
	signSharedKey(cross, "owned", keyA)
	crossRec := httptest.NewRecorder()
	mux.ServeHTTP(crossRec, cross)
	if crossRec.Code != http.StatusForbidden || strings.Contains(crossRec.Body.String(), "other-blob-bytes") || strings.Contains(crossRec.Body.String(), otherKey) {
		t.Fatalf("shared key cross account %d %s", crossRec.Code, crossRec.Body.String())
	}

	for _, tok := range []string{blobTok, noneTok} {
		miss := serve(mux, http.MethodGet, "/blob/no-such-acct/c1/obj", tok, "")
		body := miss.Body.String()
		if miss.Code != http.StatusNotFound || strings.Contains(body, keyA) || strings.Contains(body, otherKey) || strings.Contains(body, "other-blob-bytes") || strings.Contains(body, "owned-blob-bytes") {
			t.Fatalf("missing blob %d %s", miss.Code, body)
		}
	}

	ambig := httptest.NewRequest(http.MethodGet, "/blob/owned/c1/obj", nil)
	signSharedKey(ambig, "owned", keyA)
	ambigRec := httptest.NewRecorder()
	mux.ServeHTTP(ambigRec, ambig)
	if ambigRec.Code != http.StatusNotFound || strings.Contains(ambigRec.Body.String(), "owned-blob-bytes") || strings.Contains(ambigRec.Body.String(), keyA) {
		t.Fatalf("ambiguous shared key %d %s", ambigRec.Code, ambigRec.Body.String())
	}
	ambigBearer := serve(mux, http.MethodGet, "/blob/owned/c1/obj", "root-token", "")
	if ambigBearer.Code != http.StatusNotFound || strings.Contains(ambigBearer.Body.String(), "owned-blob-bytes") || strings.Contains(ambigBearer.Body.String(), keyA) {
		t.Fatalf("ambiguous bearer %d %s", ambigBearer.Code, ambigBearer.Body.String())
	}
}

func serve(mux http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}
