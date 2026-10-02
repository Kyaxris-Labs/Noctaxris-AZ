package eventgrid

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/httpegress"
)

func handshakeWebhook(destURL, validationCode string) error {
	if strings.TrimSpace(destURL) == "" {
		return nil
	}
	if err := httpegress.Allowed(destURL); err != nil {
		return fmt.Errorf("webhook destination not allowed: %w", err)
	}
	if validationCode == "" {
		validationCode = newValidationCode()
	}
	payload := []map[string]any{{
		"id":          newValidationCode(),
		"eventType":   "Microsoft.EventGrid.SubscriptionValidationEvent",
		"subject":     "",
		"eventTime":   time.Now().UTC().Format(time.RFC3339),
		"dataVersion": "1",
		"data": map[string]any{
			"validationCode": validationCode,
		},
	}}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, destURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("aeg-event-type", "SubscriptionValidation")
	client := httpegress.Client(5 * time.Second)
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("validation webhook status %d", res.StatusCode)
	}
	var resp struct {
		ValidationResponse string `json:"validationResponse"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("validation response JSON: %w", err)
	}
	if strings.TrimSpace(resp.ValidationResponse) != validationCode {
		return fmt.Errorf("validationResponse mismatch")
	}
	return nil
}

func newValidationCode() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
