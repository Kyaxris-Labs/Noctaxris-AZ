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
