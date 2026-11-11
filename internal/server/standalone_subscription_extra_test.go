package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestStandaloneSubscriptionStorageListKeys(t *testing.T) {
	srv, cfg, st := standaloneServerStore(t, true)
	h := srv.Handler()
	if err := st.UpsertResourceGroup(cfg.SubscriptionID, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}
	seeded := decodeSeed(t, postStandalone(t, h, cfg.RootAccessToken, []byte(`{"name":"home"}`)))
	if err := st.UpsertResourceGroup(seeded.SubscriptionID, "rg-home", "eastus"); err != nil {
		t.Fatal(err)
	}

	const account = "homekeysacct"
	homeKey, err := st.UpsertStorageAccount(seeded.SubscriptionID, "rg-home", account, "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	if homeKey == "" || homeKey == cfg.RootAccessToken {
		t.Fatal("storage account key missing")
	}

	homePath := "/subscriptions/" + seeded.SubscriptionID + "/resourceGroups/rg-home/providers/Microsoft.Storage/storageAccounts/" + account + "/listKeys"
	ownerKeys := authedWrite(t, h, http.MethodPost, homePath, seeded.AccessToken, "")
	if ownerKeys.Code != http.StatusOK || !strings.Contains(ownerKeys.Body.String(), homeKey) {
		t.Fatalf("owner listKeys %d leaked=%v", ownerKeys.Code, strings.Contains(ownerKeys.Body.String(), homeKey))
	}

	labPath := "/subscriptions/" + cfg.SubscriptionID + "/resourceGroups/rg-lab/providers/Microsoft.Storage/storageAccounts/" + account + "/listKeys"
	labKeys := authedWrite(t, h, http.MethodPost, labPath, seeded.AccessToken, "")
	if labKeys.Code != http.StatusForbidden && labKeys.Code != http.StatusNotFound {
		t.Fatalf("lab listKeys %d %s", labKeys.Code, labKeys.Body.String())
	}
	if strings.Contains(labKeys.Body.String(), homeKey) {
		t.Fatalf("lab listKeys status=%d returned the storage account key", labKeys.Code)
	}

	accountID := "/subscriptions/" + seeded.SubscriptionID + "/resourceGroups/rg-home/providers/Microsoft.Storage/storageAccounts/" + account
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-home-reader", Scope: accountID, RoleDefinitionID: authz.RoleReader,
		PrincipalID: "sp-home-reader", PrincipalType: "ServicePrincipal",
	}); err != nil {
		t.Fatal(err)
	}
	es := &entra.Service{Store: st, TenantID: cfg.TenantID}
	readerTok, _, err := es.MintAccessToken("sp-home-reader", authn.AudienceARM)
	if err != nil {
		t.Fatal(err)
	}
	if readerTok == "" || readerTok == seeded.AccessToken || readerTok == cfg.RootAccessToken {
		t.Fatal("reader token missing or reused")
	}
	readerKeys := authedWrite(t, h, http.MethodPost, homePath, readerTok, "")
	if readerKeys.Code != http.StatusForbidden || strings.Contains(readerKeys.Body.String(), homeKey) {
		t.Fatalf("reader listKeys %d leaked=%v", readerKeys.Code, strings.Contains(readerKeys.Body.String(), homeKey))
	}
}

func TestStandaloneSubscriptionNamespaceKeyScope(t *testing.T) {
	srv, cfg, st := standaloneServerStore(t, true)
	h := srv.Handler()
	if err := st.UpsertResourceGroup(cfg.SubscriptionID, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}
	seeded := decodeSeed(t, postStandalone(t, h, cfg.RootAccessToken, []byte(`{"name":"home"}`)))
	if err := st.UpsertResourceGroup(seeded.SubscriptionID, "rg-home", "eastus"); err != nil {
		t.Fatal(err)
	}

	const ns = "labonlyns"
	labKey, err := st.UpsertServiceBusNamespace(cfg.SubscriptionID, "rg-lab", ns, "eastus")
	if err != nil {
		t.Fatal(err)
	}
	if labKey == "" {
		t.Fatal("lab namespace key missing")
	}

	csPath := "/subscriptions/" + seeded.SubscriptionID + "/resourceGroups/rg-home/providers/Microsoft.ServiceBus/namespaces/" + ns + "/connectionString"
	cs := authedGET(t, h, csPath, seeded.AccessToken)
	csBody := cs.Body.String()
	if cs.Code != http.StatusNotFound || strings.Contains(csBody, "SharedAccessKey") || strings.Contains(csBody, labKey) {
		if strings.Contains(csBody, "SharedAccessKey") || strings.Contains(csBody, labKey) {
			t.Fatalf("connection string status=%d leaked key material", cs.Code)
		}
		t.Fatalf("connection string %d %s", cs.Code, csBody)
	}

	putPath := "/subscriptions/" + seeded.SubscriptionID + "/resourceGroups/rg-home/providers/Microsoft.ServiceBus/namespaces/" + ns
	created := authedWrite(t, h, http.MethodPut, putPath, seeded.AccessToken, `{"location":"eastus"}`)
	createdBody := created.Body.String()
	if created.Code != http.StatusConflict || strings.Contains(createdBody, "SharedAccessKey") || strings.Contains(createdBody, labKey) {
		if strings.Contains(createdBody, "SharedAccessKey") || strings.Contains(createdBody, labKey) {
			t.Fatalf("namespace create status=%d leaked key material", created.Code)
		}
		t.Fatalf("namespace create %d %s", created.Code, createdBody)
	}
}

func authedWrite(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
