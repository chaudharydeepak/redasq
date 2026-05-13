package mlclassifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Result is the parsed verdict from a single classification call.
// Stored as JSON on the prompts row (column: ml_classification).
type Result struct {
	Sensitive bool   `json:"sensitive"`
	Category  string `json:"category"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Model     string `json:"model,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Client is a thin HTTP wrapper around llama-server's OpenAI-compat endpoint.
type Client struct {
	URL  string // base URL, e.g. http://127.0.0.1:8765
	http *http.Client
}

// New returns a Client pointed at the given base URL. The caller is
// responsible for ensuring the server is reachable (see Health).
func New(baseURL string) *Client {
	return &Client{
		URL:  baseURL,
		http: &http.Client{Timeout: 120 * time.Second},
	}
}

// Health pings /health and returns nil when the server reports ready.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: %s", resp.Status)
	}
	return nil
}

// Classify runs the model on a single text input. Returns a Result with the
// parsed verdict plus measured wall-clock latency. text must be non-empty.
func (c *Client) Classify(ctx context.Context, text string) (*Result, error) {
	if text == "" {
		return nil, errors.New("classify: empty text")
	}

	var schema json.RawMessage
	if err := json.Unmarshal([]byte(ResponseSchemaJSON), &schema); err != nil {
		return nil, fmt.Errorf("classify: schema: %w", err)
	}

	body := map[string]any{
		"messages": []map[string]string{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": text},
		},
		"temperature": 0,
		"max_tokens":  60,
		"stream":      false,
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "classification",
				"schema": schema,
				"strict": true,
			},
		},
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("classify: %s: %s", resp.Status, string(b))
	}

	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	if len(envelope.Choices) == 0 {
		return nil, errors.New("classify: no choices in response")
	}

	var r Result
	if err := json.Unmarshal([]byte(envelope.Choices[0].Message.Content), &r); err != nil {
		return nil, fmt.Errorf("classify: parse content: %w", err)
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	r.Model = envelope.Model
	return &r, nil
}
