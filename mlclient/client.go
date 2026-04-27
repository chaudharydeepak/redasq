// Package mlclient is the proxy's HTTP client for the DistilBERT classifier
// sidecar (ml/classifier_server.py). Predictions are advisory: the regex
// engine remains the sole authority for block/redact decisions.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Prediction mirrors the JSON returned by POST /classify.
type Prediction struct {
	Scores         map[string]float64 `json:"scores"`
	AboveThreshold []string           `json:"above_threshold"`
	TopLabel       string             `json:"top_label"`
	TopScore       float64            `json:"top_score"`
	LatencyMS      int                `json:"latency_ms"`
}

// Client posts prompts to the classifier sidecar.
type Client struct {
	url  string
	http *http.Client
}

// New returns a client targeting url. A zero or negative timeout defaults to 2s.
func New(url string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Client{
		url:  url,
		http: &http.Client{Timeout: timeout},
	}
}

// URL returns the configured endpoint.
func (c *Client) URL() string { return c.url }

// Classify posts text to the sidecar and returns the parsed prediction.
func (c *Client) Classify(ctx context.Context, text string) (*Prediction, error) {
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: text})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("classifier %d: %s", resp.StatusCode, string(buf))
	}
	var p Prediction
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
