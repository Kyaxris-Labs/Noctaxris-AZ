package sdk_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLabClockAndBulkSeedSmoke(t *testing.T) {
	ep := requireReady(t)
	token := requireToken(t)
	flag := strings.ToLower(strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_LAB_FORENSICS")))
	if flag != "1" && flag != "true" {
		t.Skip("NOCTAXRIS_AZ_LAB_FORENSICS unset; soft-skip live clock/BulkSeed")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	fixed := "2020-01-02T03:04:05Z"
	setBody, _ := json.Marshal(map[string]string{"fixedTime": fixed})
	req, err := http.NewRequest(http.MethodPost, ep+"/_noctaxris-az/lab/clock:set", bytes.NewReader(setBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clock:set status=%d body=%s", resp.StatusCode, body)
	}

	seed, _ := json.Marshal(map[string]string{"scenarioId": "suspicious-signin"})
	req, err = http.NewRequest(http.MethodPost, ep+"/_noctaxris-az/lab/bulkSeed", bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulkSeed status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "suspicious-signin") {
		t.Fatalf("bulkSeed body=%s", body)
	}

	req, err = http.NewRequest(http.MethodPost, ep+"/_noctaxris-az/lab/clock:unfreeze", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clock:unfreeze status=%d", resp.StatusCode)
	}
}
