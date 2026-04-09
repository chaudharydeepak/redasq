package proxy

import (
	"encoding/json"
	"regexp"
	"strings"
)

var xmlTagRe = regexp.MustCompile(`<[^>]+>`)

// IsStreaming reports whether the request body uses SSE streaming.
func IsStreaming(body []byte) bool {
	var req struct {
		Stream bool `json:"stream"`
	}
	json.Unmarshal(body, &req)
	return req.Stream
}

// ExtractPrompts returns the inspectable text from the current turn of an
// OpenAI (/v1/chat/completions) or Anthropic (/v1/messages) request.
//
// "Current turn" = all content after the last assistant message. This avoids
// re-flagging conversation history on every subsequent request.
//
// Both formats share the messages array structure. Key differences handled:
//   - Anthropic has a top-level "system" field (not a message role)
//   - Anthropic content blocks use tool_result with nested content arrays
//   - Copilot injects XML context into message content — stripped before returning
func ExtractPrompts(body []byte) []string {
	if len(body) == 0 {
		return nil
	}

	var envelope struct {
		System   json.RawMessage `json:"system"` // Anthropic only — string or block array
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Prompt string `json:"prompt"` // OpenAI legacy completion
		Input  string `json:"input"`  // generic
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	// Find the last assistant message. Everything after it is the current turn.
	lastAssistant := -1
	for i := len(envelope.Messages) - 1; i >= 0; i-- {
		if envelope.Messages[i].Role == "assistant" {
			lastAssistant = i
			break
		}
	}

	var raw []string

	// Include Anthropic system prompt on the first turn only.
	// On subsequent turns it has already been sent and inspected.
	if lastAssistant == -1 && len(envelope.System) > 0 {
		raw = append(raw, extractContentText(envelope.System)...)
	}

	// Current turn: all messages after the last assistant message.
	for i := lastAssistant + 1; i < len(envelope.Messages); i++ {
		raw = append(raw, extractContentText(envelope.Messages[i].Content)...)
	}

	// Legacy/generic top-level fields.
	if envelope.Prompt != "" {
		raw = append(raw, envelope.Prompt)
	}
	if envelope.Input != "" {
		raw = append(raw, envelope.Input)
	}

	return cleanTexts(raw)
}

// extractContentText recursively pulls plain text out of a content field.
//
// Supported shapes:
//
//	string              — bare text (both formats)
//	[]{type,text}       — OpenAI content parts / Anthropic content blocks
//	tool_result block   — Anthropic; nested content is a string or block array
//
// Skipped: image, image_url, audio, tool_use (no inspectable plain text).
func extractContentText(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	// Bare string.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t := strings.TrimSpace(s); t != "" {
			return []string{t}
		}
		return nil
	}

	// Array of content blocks or parts.
	var blocks []struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`    // text / text_delta
		Content json.RawMessage `json:"content"` // tool_result nested payload
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return nil
	}

	var out []string
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if t := strings.TrimSpace(b.Text); t != "" {
				out = append(out, t)
			}
		case "tool_result":
			// Anthropic tool_result content is a string or content block array.
			out = append(out, extractContentText(b.Content)...)
		// Deliberately skipped:
		// "image", "image_url"  — binary, no text
		// "audio"               — binary, no text
		// "tool_use"            — function call schema, not user data
		}
	}
	return out
}

// cleanTexts strips XML markup injected by tools like Copilot, collapses
// whitespace, deduplicates, and drops blank entries.
func cleanTexts(texts []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, t := range texts {
		t = strings.Join(strings.Fields(xmlTagRe.ReplaceAllString(t, " ")), " ")
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// ExtractUserQuery returns only the user's actual typed message from the current
// turn — suitable for display in the dashboard. Unlike ExtractPrompts it does not
// include injected file context or system instructions.
//
// For Copilot's XML-wrapped format, the <user_query> tag is preferred.
// For plain OpenAI / Anthropic requests the user message text is returned as-is.
func ExtractUserQuery(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var envelope struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Prompt string `json:"prompt"`
		Input  string `json:"input"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}

	// Find the last assistant message — current turn is everything after it.
	lastAssistant := -1
	for i := len(envelope.Messages) - 1; i >= 0; i-- {
		if envelope.Messages[i].Role == "assistant" {
			lastAssistant = i
			break
		}
	}

	var parts []string
	for i := lastAssistant + 1; i < len(envelope.Messages); i++ {
		if envelope.Messages[i].Role != "user" {
			continue
		}
		if t := userQueryFromContent(envelope.Messages[i].Content); t != "" {
			parts = append(parts, t)
		}
	}

	if len(parts) == 0 {
		if envelope.Prompt != "" {
			return envelope.Prompt
		}
		return envelope.Input
	}
	return strings.Join(parts, "\n\n")
}

// userQueryFromContent extracts the display-worthy user text from a content field.
// Prefers <user_query> tag (Copilot), then falls back to stripping XML.
func userQueryFromContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var s string
	if json.Unmarshal(raw, &s) == nil {
		return userQueryFromString(s)
	}

	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}

	// First pass: if any block contains a <user_query> tag, return only that.
	for _, b := range blocks {
		if b.Type == "text" {
			if t := extractUserQueryTag(b.Text); t != "" {
				return t
			}
		}
	}

	// No <user_query> tag found — strip XML from all blocks and join.
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			if t := strings.Join(strings.Fields(xmlTagRe.ReplaceAllString(b.Text, " ")), " "); t != "" {
				parts = append(parts, t)
			}
		}
	}
	return strings.Join(parts, "\n\n")
}

// extractUserQueryTag returns the content of the first <user_query>…</user_query>
// tag in s, or "" if not present.
func extractUserQueryTag(s string) string {
	const open, close = "<user_query>", "</user_query>"
	if start := strings.Index(s, open); start >= 0 {
		rest := s[start+len(open):]
		if end := strings.Index(rest, close); end >= 0 {
			return strings.TrimSpace(rest[:end])
		}
	}
	return ""
}

// ExtractUsage parses input/output token counts from a response body.
// Handles Anthropic and OpenAI formats for both plain JSON and SSE streams.
func ExtractUsage(body []byte) (inputTokens, outputTokens int) {
	type usageBlock struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		PromptTokens             int `json:"prompt_tokens"`
		CompletionTokens         int `json:"completion_tokens"`
	}
	type lineShape struct {
		Usage   *usageBlock `json:"usage"`
		Message *struct {
			Usage *usageBlock `json:"usage"`
		} `json:"message"`
	}

	// Scan each line — works for both plain JSON and SSE (data: {...}).
	// Fresh struct per line so stale pointer fields from prior iterations don't bleed through.
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "data: ")
		if line == "" || line == "[DONE]" {
			continue
		}
		var s lineShape
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			continue
		}
		// Anthropic message_start: usage nested under message
		if s.Message != nil && s.Message.Usage != nil {
			u := s.Message.Usage
			if total := u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens; total > inputTokens {
				inputTokens = total
			}
		}
		if s.Usage != nil {
			u := s.Usage
			// Anthropic top-level usage (message_delta has output_tokens; non-streaming has both)
			if total := u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens; total > inputTokens {
				inputTokens = total
			}
			if u.OutputTokens > outputTokens {
				outputTokens = u.OutputTokens
			}
			// OpenAI / Copilot
			if u.PromptTokens > inputTokens {
				inputTokens = u.PromptTokens
			}
			if u.CompletionTokens > outputTokens {
				outputTokens = u.CompletionTokens
			}
		}
	}
	return
}


// ExtractModel returns the model name from an OpenAI or Anthropic request body.
func ExtractModel(body []byte) string {
	var req struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &req)
	return req.Model
}

// ExtractAnthropicSessionID pulls the session_id from the metadata.user_id field
// that Claude Code embeds in every /v1/messages request body.
// The user_id field is a JSON-encoded string: {"device_id":"...","session_id":"..."}
func ExtractAnthropicSessionID(body []byte) string {
	var env struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Metadata.UserID == "" {
		return ""
	}
	var inner struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(env.Metadata.UserID), &inner); err != nil {
		return ""
	}
	return inner.SessionID
}

// userQueryFromString extracts the user message from a string content field.
// Uses <user_query> tag when present (Copilot format); otherwise strips XML tags.
func userQueryFromString(s string) string {
	if t := extractUserQueryTag(s); t != "" {
		return t
	}
	return strings.Join(strings.Fields(xmlTagRe.ReplaceAllString(s, " ")), " ")
}
