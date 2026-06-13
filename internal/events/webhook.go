package events

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// DeliveryResult represents the outcome of a webhook delivery attempt.
type DeliveryResult struct {
	DeliveryID string
	StatusCode int
	Retryable  bool
	Success    bool
	Error      error
}

// WebhookSender delivers events via HTTP webhook with optional HMAC-SHA256 signing.
type WebhookSender struct {
	client *http.Client
}

// NewWebhookSender creates a new WebhookSender with the given timeout.
func NewWebhookSender(timeout time.Duration) *WebhookSender {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &WebhookSender{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Send delivers the event to the configured webhook URL.
// It returns a DeliveryResult indicating success/failure and retryability.
func (s *WebhookSender) Send(event *Event, dest DestinationConfig) DeliveryResult {
	deliveryID := uuid.New().String()

	payload, err := json.Marshal(event)
	if err != nil {
		return DeliveryResult{
			DeliveryID: deliveryID,
			Success:    false,
			Retryable:  false,
			Error:      fmt.Errorf("failed to marshal event: %w", err),
		}
	}

	req, err := http.NewRequest("POST", dest.URL, bytes.NewReader(payload))
	if err != nil {
		return DeliveryResult{
			DeliveryID: deliveryID,
			Success:    false,
			Retryable:  false,
			Error:      fmt.Errorf("failed to create request: %w", err),
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nexus-Delivery", deliveryID)
	req.Header.Set("X-Nexus-Event-Type", event.EventType)

	// Sign payload if signing config is provided
	if dest.Signing != nil && dest.Signing.Secret != "" {
		sig := signPayload(payload, dest.Signing.Secret)
		req.Header.Set("X-Nexus-Signature", sig)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return DeliveryResult{
			DeliveryID: deliveryID,
			Success:    false,
			Retryable:  true,
			Error:      fmt.Errorf("request failed: %w", err),
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	retryable := false

	if !success {
		// 5xx is retryable
		if resp.StatusCode >= 500 {
			retryable = true
		}
		// 429 (Too Many Requests) is retryable
		if resp.StatusCode == 429 {
			retryable = true
		}
		// Other 4xx are non-retryable
	}

	return DeliveryResult{
		DeliveryID: deliveryID,
		StatusCode: resp.StatusCode,
		Retryable:  retryable,
		Success:    success,
	}
}

// signPayload computes the HMAC-SHA256 signature of the payload using the given secret.
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies the HMAC-SHA256 signature of a payload.
func VerifySignature(payload []byte, secret, signature string) bool {
	expected := signPayload(payload, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}
