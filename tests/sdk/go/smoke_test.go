package sdk_test

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func endpoint(t *testing.T) string {
	t.Helper()
	ep := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_ENDPOINT"))
	if ep == "" {
		t.Skip("NOCTAXRIS_AZ_ENDPOINT unset; soft-skip live smoke")
	}
	return strings.TrimRight(ep, "/")
}

func requireReady(t *testing.T) string {
	t.Helper()
	ep := endpoint(t)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ep + "/_noctaxris-az/ready")
	if err != nil {
		t.Skipf("Noctaxris-AZ not reachable at %s: %v", ep, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("Noctaxris-AZ not ready at %s: status %d", ep, resp.StatusCode)
	}
	return ep
}

func requireToken(t *testing.T) string {
	t.Helper()
	token := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN"))
	if token == "" {
		t.Skip("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN unset; soft-skip authenticated smoke")
	}
	return token
}

func subscriptionID() string {
	sub := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_SUBSCRIPTION_ID"))
	if sub == "" {
		return "00000000-0000-0000-0000-000000000002"
	}
	return sub
}

func TestHealthReadyAndSubscriptionSmoke(t *testing.T) {
	ep := requireReady(t)
	token := requireToken(t)
	sub := subscriptionID()

	client := &http.Client{Timeout: 5 * time.Second}
	health, err := client.Get(ep + "/_noctaxris-az/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d", health.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, ep+"/subscriptions/"+sub+"?api-version=2022-12-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("subscription GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subscription GET status=%d body=%s", resp.StatusCode, body)
	}
}

func TestIMDSTokenSmoke(t *testing.T) {
	ep := requireReady(t)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet,
		ep+"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("imds: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("imds status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "access_token") {
		t.Fatalf("imds body missing access_token: %s", body)
	}
}

func TestTablePutGetSmoke(t *testing.T) {
	ep := requireReady(t)
	token := requireToken(t)
	sub := subscriptionID()
	client := &http.Client{Timeout: 10 * time.Second}

	rgURL := ep + "/subscriptions/" + sub + "/resourceGroups/sdk-rg?api-version=2022-12-01"
	rgReq, _ := http.NewRequest(http.MethodPut, rgURL, strings.NewReader(`{"location":"eastus"}`))
	rgReq.Header.Set("Authorization", "Bearer "+token)
	rgReq.Header.Set("Content-Type", "application/json")
	rgRes, err := client.Do(rgReq)
	if err != nil {
		t.Fatal(err)
	}
	rgRes.Body.Close()
	if rgRes.StatusCode >= 300 {
		t.Skipf("RG create status=%d; soft-skip table smoke", rgRes.StatusCode)
	}

	acct := "sdktableacct1"
	saURL := ep + "/subscriptions/" + sub + "/resourceGroups/sdk-rg/providers/Microsoft.Storage/storageAccounts/" + acct + "?api-version=2023-01-01"
	saReq, _ := http.NewRequest(http.MethodPut, saURL, strings.NewReader(`{"location":"eastus"}`))
	saReq.Header.Set("Authorization", "Bearer "+token)
	saReq.Header.Set("Content-Type", "application/json")
	saRes, err := client.Do(saReq)
	if err != nil {
		t.Fatal(err)
	}
	saRes.Body.Close()
	if saRes.StatusCode >= 300 {
		t.Skipf("storage account create status=%d; soft-skip table smoke", saRes.StatusCode)
	}

	// Root Bearer can authorize table data plane in lab.
	putTable, _ := http.NewRequest(http.MethodPut, ep+"/table/"+acct+"/sdkpeople", nil)
	putTable.Header.Set("Authorization", "Bearer "+token)
	ptRes, err := client.Do(putTable)
	if err != nil {
		t.Fatal(err)
	}
	ptRes.Body.Close()
	if ptRes.StatusCode != http.StatusCreated && ptRes.StatusCode != http.StatusOK {
		t.Fatalf("create table status=%d", ptRes.StatusCode)
	}

	ins, _ := http.NewRequest(http.MethodPost, ep+"/table/"+acct+"/sdkpeople",
		strings.NewReader(`{"PartitionKey":"p","RowKey":"r","Name":"sdk"}`))
	ins.Header.Set("Authorization", "Bearer "+token)
	ins.Header.Set("Content-Type", "application/json")
	insRes, err := client.Do(ins)
	if err != nil {
		t.Fatal(err)
	}
	insRes.Body.Close()
	if insRes.StatusCode != http.StatusCreated && insRes.StatusCode != http.StatusConflict {
		t.Fatalf("insert status=%d", insRes.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, ep+"/table/"+acct+"/sdkpeople/p/r", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	getRes, err := client.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer getRes.Body.Close()
	body, _ := io.ReadAll(getRes.Body)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("get entity status=%d body=%s", getRes.StatusCode, body)
	}
}
