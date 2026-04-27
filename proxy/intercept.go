package proxy

import (
	"encoding/json"
	"regexp"
	"strings"
)

var xmlTagRe = regexp.MustCompile(`<[^>]+>`)

// harnessBlockRe strips wrapper blocks injected by client harnesses around the
// user's actual typed text. Both the tags AND the content are removed (unlike
// xmlTagRe which keeps content) — these blocks carry meta context, not user
// input, and leaving them in pollutes both the dashboard prompt display and
// the ML classifier input.
//
// Supported wrappers:
//   <system-reminder>      — Claude Code harness reminders
//   <command-name|message|args>, <local-command-stdout|stderr> — Claude Code slash-cmd metadata
//   <context>              — Copilot (everything except <user_query>)
//   <environment_details>  — Cline / similar agents
//
// Go regexp lacks backreferences, so each open/close pair gets its own branch.
var harnessBlockRe = regexp.MustCompile(`(?s)` +
	`<system-reminder\b[^>]*>.*?</system-reminder>` +
	`|<command-name\b[^>]*>.*?</command-name>` +
	`|<command-message\b[^>]*>.*?</command-message>` +
	`|<command-args\b[^>]*>.*?</command-args>` +
	`|<local-command-stdout\b[^>]*>.*?</local-command-stdout>` +
	`|<local-command-stderr\b[^>]*>.*?</local-command-stderr>` +
	`|<context\b[^>]*>.*?</context>` +
	`|<environment_details\b[^>]*>.*?</environment_details>`)

func stripHarnessWrappers(s string) string {
	return harnessBlockRe.ReplaceAllString(s, "")
}

// Request holds all fields derived from a single LLM API request body.
// Call ParseRequest once per intercepted request instead of calling individual
// Extract* functions — each previously unmarshalled the full body independently.
type Request struct {
	Model          string   // "model" field from request body
	Streaming      bool     // true when stream:true
	SessionID      string   // Anthropic session ID from metadata.user_id
	Prompts        []string // inspectable text, current turn only (for rule matching)
	UserQuery      string   // user's typed message only (for dashboard display)
	Background     bool     // Copilot internal call (title / summary) — never block
	IsContinuation bool     // tool-chain continuation request (no new user-typed text)
}

// ParseRequest parses a request body once and populates all fields in a single
// pass. Handles Anthropic /v1/messages, OpenAI /v1/chat/completions, and the
// OpenAI Responses API /responses format.
func ParseRequest(body []byte) *Request {
	r := &Request{}
	if len(body) == 0 {
		return r
	}

	var env struct {
		Model    string          `json:"model"`
		Stream   bool            `json:"stream"`
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
		Input        json.RawMessage `json:"input"`
		Instructions string          `json:"instructions"`
		Prompt       string          `json:"prompt"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return r
	}

	r.Model = env.Model
	r.Streaming = env.Stream

	// Anthropic embeds session_id as a JSON-encoded string inside metadata.user_id.
	if env.Metadata.UserID != "" {
		var inner struct {
			SessionID string `json:"session_id"`
		}
		json.Unmarshal([]byte(env.Metadata.UserID), &inner)
		r.SessionID = inner.SessionID
	}

	var rawTexts []string
	var queryParts []string

	// System prompt (Anthropic) — always inspect. Clients like Copilot refresh it
	// on every request with current file context, so secrets can appear at any turn.
	if len(env.System) > 0 {
		rawTexts = append(rawTexts, extractContentText(env.System)...)
	}

	// Messages array (Anthropic /v1/messages + OpenAI /v1/chat/completions).
	//
	// Two passes with different semantics:
	//   1. Prompts (regex inspection) — current turn only. Re-inspecting full
	//      history on every turn would re-flag the same value repeatedly.
	//   2. UserQuery (display + ML) — walk backwards from the end and pick the
	//      most recent user message that carries actual text. This is independent
	//      of "current turn": Claude Code's tool-use chains and sub-agent calls
	//      end with an assistant message, which would leave UserQuery empty
	//      under the Prompts rule even though the user typed something earlier
	//      in the conversation. Tool_result-only user messages are skipped
	//      because userQueryFromContent extracts only "text" blocks.
	if len(env.Messages) > 0 {
		lastAsst := -1
		for i := len(env.Messages) - 1; i >= 0; i-- {
			if env.Messages[i].Role == "assistant" {
				lastAsst = i
				break
			}
		}
		for i := lastAsst + 1; i < len(env.Messages); i++ {
			msg := env.Messages[i]
			rawTexts = append(rawTexts, extractContentText(msg.Content)...)
			if msg.Role == "user" {
				// Copilot background detection: internal calls (title generation,
				// summarization, progress) use plain string content with known prefixes.
				var s string
				if json.Unmarshal(msg.Content, &s) == nil {
					t := strings.TrimSpace(s)
					if strings.HasPrefix(t, "Summarize the following") ||
						strings.HasPrefix(t, "Please write a brief title") ||
						strings.HasPrefix(t, "Please generate exactly") {
						r.Background = true
					}
				}
			}
		}
		// UserQuery: text from the LAST message only, and only if it's a user
		// message that carries actual text. We deliberately do NOT walk back
		// into history: Claude Code (and other clients) re-send the full
		// conversation on every API call, so walking back would attribute the
		// parent turn's typed text to every tool-chain continuation request,
		// producing visible duplicates in the dashboard. Continuations are
		// flagged separately via IsContinuation below.
		last := env.Messages[len(env.Messages)-1]
		if last.Role == "user" {
			if q := userQueryFromContent(last.Content); q != "" {
				queryParts = append(queryParts, q)
			} else {
				// Last message is a user message with no text content — only
				// tool_result blocks. That's a Claude-Code-style tool-chain
				// continuation; no new typed input from the user.
				r.IsContinuation = true
			}
		} else {
			// Last message isn't a user message — the request is not asking
			// the model to respond to typed input. Treat as continuation.
			r.IsContinuation = true
		}
	}

	// OpenAI Responses API: input is either a plain string or an array of items.
	if len(env.Input) > 0 {
		var inputStr string
		if json.Unmarshal(env.Input, &inputStr) == nil {
			// Plain string input.
			if env.Instructions != "" {
				rawTexts = append(rawTexts, env.Instructions)
			}
			if inputStr != "" {
				rawTexts = append(rawTexts, inputStr)
				queryParts = append(queryParts, userQueryFromString(inputStr))
			}
		} else {
			// Array of input items.
			var items []struct {
				Role    string `json:"role"`
				Type    string `json:"type"`   // "function_call" | "function_call_output"
				Output  string `json:"output"` // function_call_output payload
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			if json.Unmarshal(env.Input, &items) == nil {
				// Prompts (regex inspection): current turn only — everything after
				// the last assistant message OR function_call (tool boundary).
				lastAsstPrompt := -1
				for i := len(items) - 1; i >= 0; i-- {
					if items[i].Role == "assistant" || items[i].Type == "function_call" {
						lastAsstPrompt = i
						break
					}
				}

				// Instructions are always inspected (Copilot CLI refreshes file context here).
				if env.Instructions != "" {
					rawTexts = append(rawTexts, env.Instructions)
				}

				for i, item := range items {
					if i > lastAsstPrompt {
						if item.Type == "function_call_output" {
							if t := strings.TrimSpace(item.Output); t != "" {
								rawTexts = append(rawTexts, t)
							}
						} else {
							for _, c := range item.Content {
								if (c.Type == "input_text" || c.Type == "text") && strings.TrimSpace(c.Text) != "" {
									rawTexts = append(rawTexts, strings.TrimSpace(c.Text))
								}
							}
						}
					}
				}

				// UserQuery: text from the LAST item only, and only if it's a
				// user item with text content. Continuation detection mirrors
				// the messages-array logic: function_call_output tails or
				// text-less user tails are tool-chain continuations.
				lastIdx := len(items) - 1
				lastItem := items[lastIdx]
				if lastItem.Type == "function_call_output" || lastItem.Type == "function_call" {
					r.IsContinuation = true
				} else if lastItem.Role == "user" {
					var part string
					for _, c := range lastItem.Content {
						if (c.Type == "input_text" || c.Type == "text") && strings.TrimSpace(c.Text) != "" {
							part = userQueryFromString(c.Text)
							break
						}
					}
					if part != "" {
						queryParts = append(queryParts, part)
					} else {
						r.IsContinuation = true
					}
				} else {
					r.IsContinuation = true
				}
			}
		}
	}

	// Legacy top-level prompt field.
	if env.Prompt != "" {
		rawTexts = append(rawTexts, env.Prompt)
	}

	r.Prompts = cleanTexts(rawTexts)

	if len(queryParts) > 0 {
		r.UserQuery = strings.Join(queryParts, "\n\n")
	} else if env.Prompt != "" {
		r.UserQuery = env.Prompt
	}

	// Final guard: any inspectable content with no extracted user query is
	// effectively a no-typed-input request. Covers system-only bodies (context
	// compaction, sub-agent spawning) that have neither messages nor input.
	if r.UserQuery == "" && len(r.Prompts) > 0 {
		r.IsContinuation = true
	}

	return r
}

// ── Compatibility wrappers ────────────────────────────────────────────────────
// These exist so existing tests keep compiling. Prefer ParseRequest for new code.

func ExtractPrompts(body []byte) []string { return ParseRequest(body).Prompts }
func ExtractUserQuery(body []byte) string  { return ParseRequest(body).UserQuery }
func IsStreaming(body []byte) bool         { return ParseRequest(body).Streaming }

// ── Private helpers ───────────────────────────────────────────────────────────

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

	// No <user_query> tag — strip harness wrappers, then XML tags, and join.
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			text := stripHarnessWrappers(b.Text)
			if t := strings.Join(strings.Fields(xmlTagRe.ReplaceAllString(text, " ")), " "); t != "" {
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

// userQueryFromString extracts the user message from a string content field.
// Uses <user_query> tag when present (Copilot format); otherwise strips
// harness wrapper blocks and XML tags so the result is the user's actual text.
func userQueryFromString(s string) string {
	if t := extractUserQueryTag(s); t != "" {
		return t
	}
	s = stripHarnessWrappers(s)
	return strings.Join(strings.Fields(xmlTagRe.ReplaceAllString(s, " ")), " ")
}

// ── Response-side functions ───────────────────────────────────────────────────

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
		// OpenAI Responses API: response.completed event
		Response *struct {
			Usage *usageBlock `json:"usage"`
		} `json:"response"`
	}

	for _, line := range sseLines(body) {
		var s lineShape
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			continue
		}
		// Anthropic message_start: usage nested under message.
		if s.Message != nil && s.Message.Usage != nil {
			u := s.Message.Usage
			if total := u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens; total > inputTokens {
				inputTokens = total
			}
		}
		if s.Usage != nil {
			u := s.Usage
			if total := u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens; total > inputTokens {
				inputTokens = total
			}
			if u.OutputTokens > outputTokens {
				outputTokens = u.OutputTokens
			}
			if u.PromptTokens > inputTokens {
				inputTokens = u.PromptTokens
			}
			if u.CompletionTokens > outputTokens {
				outputTokens = u.CompletionTokens
			}
		}
		// OpenAI Responses API: usage nested under response.
		if s.Response != nil && s.Response.Usage != nil {
			u := s.Response.Usage
			if u.InputTokens > inputTokens {
				inputTokens = u.InputTokens
			}
			if u.OutputTokens > outputTokens {
				outputTokens = u.OutputTokens
			}
		}
	}
	return
}

// ExtractResponseText pulls plain text from an LLM response body.
// Handles Anthropic and OpenAI SSE streams as well as plain JSON responses.
// Captures both text content and tool calls (formatted as [Tool: name]\n<input>).
// Returns the full assembled text — no truncation.
func ExtractResponseText(body []byte) string {
	var out strings.Builder

	// Try plain JSON first (non-streaming response).
	var plain struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			Name  string          `json:"name"`  // tool_use
			Input json.RawMessage `json:"input"` // tool_use
		} `json:"content"`
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &plain) == nil {
		for _, c := range plain.Content {
			switch c.Type {
			case "text":
				out.WriteString(c.Text)
			case "tool_use":
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				out.WriteString("[Tool: " + c.Name + "]\n")
				if len(c.Input) > 0 && string(c.Input) != "null" {
					out.Write(c.Input)
					out.WriteString("\n")
				}
			}
		}
		for _, c := range plain.Choices {
			out.WriteString(c.Message.Content)
			for _, tc := range c.Message.ToolCalls {
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				out.WriteString("[Tool: " + tc.Function.Name + "]\n")
				if tc.Function.Arguments != "" {
					out.WriteString(tc.Function.Arguments + "\n")
				}
			}
		}
		if out.Len() > 0 {
			return out.String()
		}
	}

	// SSE stream — scan each data: line.
	// toolNames/toolInputs track in-flight tool_use blocks by index (Anthropic streaming).
	toolNames  := map[int]string{}
	toolInputs := map[int]*strings.Builder{}
	type sseEvent struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"content_block"`
		Delta   json.RawMessage `json:"delta"`
		Choices []struct {
			Delta struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	for _, line := range sseLines(body) {
		var ev sseEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "content_block_start":
			if ev.ContentBlock.Type == "tool_use" {
				toolNames[ev.Index] = ev.ContentBlock.Name
				toolInputs[ev.Index] = &strings.Builder{}
			}
		case "content_block_delta":
			if len(ev.Delta) > 0 && ev.Delta[0] == '{' {
				var obj struct {
					Type        string `json:"type"`
					Text        string `json:"text"`
					PartialJSON string `json:"partial_json"`
				}
				if json.Unmarshal(ev.Delta, &obj) == nil {
					switch obj.Type {
					case "text_delta":
						out.WriteString(obj.Text)
					case "input_json_delta":
						if b, ok := toolInputs[ev.Index]; ok {
							b.WriteString(obj.PartialJSON)
						}
					}
				}
			}
		case "content_block_stop":
			if name, ok := toolNames[ev.Index]; ok {
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				out.WriteString("[Tool: " + name + "]\n")
				if b, ok2 := toolInputs[ev.Index]; ok2 && b.Len() > 0 {
					out.WriteString(b.String() + "\n")
				}
				delete(toolNames, ev.Index)
				delete(toolInputs, ev.Index)
			}
		}
		// OpenAI Responses API: delta is a plain string.
		if ev.Type == "response.output_text.delta" || ev.Type == "response.text.delta" {
			var s string
			if json.Unmarshal(ev.Delta, &s) == nil && s != "" {
				out.WriteString(s)
			}
		}
		// OpenAI chat.completions streaming.
		for _, c := range ev.Choices {
			out.WriteString(c.Delta.Content)
			for _, tc := range c.Delta.ToolCalls {
				out.WriteString(tc.Function.Arguments)
			}
		}
	}

	return out.String()
}

// sseLines splits a response body into parseable JSON lines, stripping
// SSE framing ("data: " prefix, blank lines, "[DONE]" sentinels).
// Works for both plain JSON responses and SSE streams.
func sseLines(body []byte) []string {
	raw := strings.Split(string(body), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimPrefix(strings.TrimSpace(line), "data: ")
		if line == "" || line == "[DONE]" {
			continue
		}
		out = append(out, line)
	}
	return out
}
