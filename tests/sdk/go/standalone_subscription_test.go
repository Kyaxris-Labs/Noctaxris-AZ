package sdk_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStandaloneSubscriptionSDK(t *testing.T) {
	ep := requireReady(t)
	root := requireToken(t)
	lab := subscriptionID()
	client := &http.Client{Timeout: 15 * time.Second}

	first, status := postStandaloneSeed(t, client, ep, root)
	if status == http.StatusNotFound {
		t.Skip("NOCTAXRIS_AZ_LAB_STANDALONE is off")
	}
	if status != http.StatusOK {
		t.Fatalf("seed status=%d", status)
	}
	if first.SubscriptionID == "" || first.UserID == "" || first.AccessToken == "" {
		t.Fatal("seed response missing subscriptionId, userId, or accessToken")
	}
	if first.AccessToken == root {
		t.Fatal("standalone access token equals the root token")
	}

	visible := listSubscriptionIDs(t, client, ep, first.AccessToken)
	if !subscriptionListed(visible, first.SubscriptionID) {
		t.Fatal("subscription list omitted the standalone subscription")
	}
	if subscriptionListed(visible, lab) {
		t.Fatal("subscription list included the lab subscription")
	}

	rgPath := "/subscriptions/" + lab + "/resourcegroups/rg"
	status, body := authedGET(t, client, ep, first.AccessToken, rgPath+"?api-version=2021-04-01")
	if status != http.StatusForbidden {
		t.Fatalf("lab resource group status=%d body=%s", status, redactSecrets(body, root, first.AccessToken))
	}
	if extraLabResourceID(body, lab, rgPath) {
		t.Fatal("lab resource group response includes a lab resource id other than the request URL")
	}

	second, status := postStandaloneSeed(t, client, ep, root)
	if status != http.StatusOK {
		t.Fatalf("repeat seed status=%d", status)
	}
	if second.AccessToken != first.AccessToken || second.SubscriptionID != first.SubscriptionID {
		t.Fatal("repeat seed changed accessToken or subscriptionId")
	}
}

type standaloneSeedBody struct {
	SubscriptionID string `json:"subscriptionId"`
	UserID         string `json:"userId"`
	AccessToken    string `json:"accessToken"`
}

func postStandaloneSeed(t *testing.T, client *http.Client, ep, root string) (standaloneSeedBody, int) {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		ep+"/_noctaxris-az/lab/subscriptions:seedStandalone",
		strings.NewReader(`{"name":"sdk-go"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+root)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("seed body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("seed status=%d body=%s", resp.StatusCode, redactSecrets(string(raw), root))
		}
		return standaloneSeedBody{}, resp.StatusCode
	}
	var seeded standaloneSeedBody
	if err := json.Unmarshal(raw, &seeded); err != nil {
		t.Fatalf("seed json: %v", err)
	}
	return seeded, resp.StatusCode
}

func listSubscriptionIDs(t *testing.T, client *http.Client, ep, token string) []string {
	t.Helper()
	status, raw := authedGET(t, client, ep, token, "/subscriptions?api-version=2022-12-01")
	if status != http.StatusOK {
		t.Fatalf("subscription list status=%d body=%s", status, redactSecrets(raw, token))
	}
	var listed struct {
		Value []struct {
			ID             string `json:"id"`
			SubscriptionID string `json:"subscriptionId"`
		} `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &listed); err != nil {
		t.Fatalf("subscription list json: %v", err)
	}
	ids := make([]string, 0, len(listed.Value)*2)
	for _, item := range listed.Value {
		if item.SubscriptionID != "" {
			ids = append(ids, item.SubscriptionID)
		}
		if item.ID != "" {
			ids = append(ids, item.ID)
		}
	}
	return ids
}

func authedGET(t *testing.T, client *http.Client, ep, token, pathAndQuery string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ep+pathAndQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", pathAndQuery, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("GET %s body: %v", pathAndQuery, err)
	}
	return resp.StatusCode, string(raw)
}

func subscriptionListed(ids []string, subscriptionID string) bool {
	want := strings.ToLower(strings.TrimSpace(subscriptionID))
	if want == "" {
		return false
	}
	resource := "/subscriptions/" + want
	for _, id := range ids {
		got := strings.ToLower(strings.TrimSpace(id))
		got = strings.Trim(got, "/")
		if got == want || got == strings.TrimPrefix(resource, "/") {
			return true
		}
		if strings.HasPrefix(got, strings.TrimPrefix(resource, "/")+"/") {
			return true
		}
	}
	return false
}

// extraLabResourceID reports whether body contains a lab resource id other than sentPath.
// A denial may echo the URL that was requested. Matching is case-insensitive.
func extraLabResourceID(body, labSubscription, sentPath string) bool {
	lower := strings.ToLower(body)
	lab := strings.ToLower(strings.TrimSpace(labSubscription))
	sent := strings.TrimRight(strings.ToLower(sentPath), "/")
	needle := "subscriptions/" + lab + "/"
	rest := lower
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			return false
		}
		start := i
		if start > 0 && rest[start-1] == '/' {
			start--
		}
		end := i + len(needle)
		for end < len(rest) && resourceIDByte(rest[end]) {
			end++
		}
		id := "/" + strings.Trim(rest[start:end], "/")
		id = strings.TrimRight(id, ".,;")
		if id != sent {
			return true
		}
		rest = rest[end:]
	}
}

func resourceIDByte(c byte) bool {
	switch c {
	case '"', '\'', ' ', '\n', '\r', '\t', '?', '<', '>', '\\', ',', ')', ']', '}', '&', '#':
		return false
	default:
		return true
	}
}

func redactSecrets(body string, secrets ...string) string {
	out := body
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, "[redacted]")
	}
	return out
}
