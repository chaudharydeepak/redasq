package inspector

import (
	"encoding/json"
	"strings"
	"testing"
)

// buildOpenAIBody wraps content in a realistic OpenAI chat/completions request body.
func buildOpenAIBody(t *testing.T, systemMsg, userMsg string) []byte {
	t.Helper()
	body := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": systemMsg},
			{"role": "user", "content": userMsg},
		},
		"stream":      true,
		"temperature": 0.7,
		"max_tokens":  4096,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("buildOpenAIBody: %v", err)
	}
	return b
}

// buildAnthropicBody wraps content in a realistic Anthropic /v1/messages request body.
func buildAnthropicBody(t *testing.T, system, userMsg string) []byte {
	t.Helper()
	body := map[string]interface{}{
		"model":      "claude-sonnet-4-6",
		"system":     system,
		"max_tokens": 8096,
		"messages": []map[string]string{
			{"role": "user", "content": userMsg},
		},
		"stream": true,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("buildAnthropicBody: %v", err)
	}
	return b
}

// secrets that must not appear in the redacted output.
var appYMLSecrets = []string{
	"Sup3rS3cr3tDBPass!",
	"GOCSPX-abcdefghijklmnopqrstuvwx",
	"r3d1sS3cr3tPass",
	"gmailAppPassw0rd!",
	"myJ4tS3cr3tK3yF0rHS512Signing!!",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

// TestRedactBody_OpenAI_ValidJSON checks that redacting an OpenAI payload
// containing application.yml content produces valid JSON and removes secrets.
func TestRedactBody_OpenAI_ValidJSON(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true) // apply all rules

	yml := loadFixture(t, "application.yml")
	body := buildOpenAIBody(t, "You are a helpful assistant.", "Here is my config:\n\n"+yml)

	redacted := eng.RedactBodyForForwarding(body)

	if !json.Valid(redacted) {
		t.Fatalf("RedactBodyForForwarding produced invalid JSON for OpenAI body.\nInput length: %d\nOutput: %s", len(body), redacted)
	}

	out := string(redacted)
	for _, secret := range appYMLSecrets {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q was not redacted from OpenAI body", secret)
		}
	}
}

// TestRedactBody_Anthropic_ValidJSON checks that redacting an Anthropic payload
// containing application.yml content produces valid JSON and removes secrets.
func TestRedactBody_Anthropic_ValidJSON(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)

	yml := loadFixture(t, "application.yml")
	body := buildAnthropicBody(t, "You are a helpful assistant.", "Review this config:\n\n"+yml)

	redacted := eng.RedactBodyForForwarding(body)

	if !json.Valid(redacted) {
		t.Fatalf("RedactBodyForForwarding produced invalid JSON for Anthropic body.\nInput length: %d\nOutput: %s", len(body), redacted)
	}

	out := string(redacted)
	for _, secret := range appYMLSecrets {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q was not redacted from Anthropic body", secret)
		}
	}
}

// TestRedactBody_NestedContent checks redaction works when secrets appear in
// nested structures (e.g. tool call results, multi-turn history).
func TestRedactBody_NestedContent(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)

	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user",   "content": "What should I do?"},
			{"role": "assistant", "content": "Here is the config context."},
			{"role": "user",   "content": "password: Sup3rS3cr3tDBPass!\naws_secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
		]
	}`)

	redacted := eng.RedactBodyForForwarding(body)

	if !json.Valid(redacted) {
		t.Fatalf("nested content: invalid JSON output: %s", redacted)
	}
	out := string(redacted)
	for _, secret := range []string{"Sup3rS3cr3tDBPass!", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"} {
		if strings.Contains(out, secret) {
			t.Errorf("nested content: secret %q not redacted", secret)
		}
	}
}

// TestRedactBody_NonJSON_FallbackWorks ensures non-JSON bodies (e.g. plain text)
// still get secrets redacted via the string-replacement fallback.
func TestRedactBody_NonJSON_FallbackWorks(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)

	body := []byte("Here is my config:\npassword: Sup3rS3cr3tDBPass!\nother: ok")
	redacted := eng.RedactBodyForForwarding(body)

	if strings.Contains(string(redacted), "Sup3rS3cr3tDBPass!") {
		t.Error("non-JSON fallback: secret was not redacted")
	}
}

// TestRedactBody_StructurePreserved checks that non-sensitive JSON fields
// (numbers, booleans, nulls, safe strings) survive redaction intact.
func TestRedactBody_StructurePreserved(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)

	body := []byte(`{"model":"gpt-4o","temperature":0.7,"max_tokens":4096,"stream":true,"n":null,"messages":[{"role":"user","content":"hello"}]}`)
	redacted := eng.RedactBodyForForwarding(body)

	if !json.Valid(redacted) {
		t.Fatalf("structure preserved: invalid JSON: %s", redacted)
	}

	var out map[string]interface{}
	json.Unmarshal(redacted, &out)

	if out["model"] != "gpt-4o" {
		t.Errorf("model field changed: got %v", out["model"])
	}
	if out["temperature"] != 0.7 {
		t.Errorf("temperature changed: got %v", out["temperature"])
	}
	if out["max_tokens"] != float64(4096) {
		t.Errorf("max_tokens changed: got %v", out["max_tokens"])
	}
	if out["stream"] != true {
		t.Errorf("stream changed: got %v", out["stream"])
	}
}
