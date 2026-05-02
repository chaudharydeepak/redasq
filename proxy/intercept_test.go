package proxy

import (
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func joined(prompts []string) string { return strings.Join(prompts, " | ") }

func containsAll(prompts []string, want ...string) bool {
	full := joined(prompts)
	for _, w := range want {
		if !strings.Contains(full, w) {
			return false
		}
	}
	return true
}

func containsNone(prompts []string, reject ...string) bool {
	full := joined(prompts)
	for _, r := range reject {
		if strings.Contains(full, r) {
			return false
		}
	}
	return true
}

// ── OpenAI /v1/chat/completions ───────────────────────────────────────────────

func TestExtract_OpenAI_StringContent(t *testing.T) {
	body := `{
		"messages": [
			{"role": "system",    "content": "You are helpful."},
			{"role": "user",      "content": "My SSN is 123-45-6789"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "My SSN is 123-45-6789") {
		t.Errorf("user message not extracted: %v", p)
	}
	// First turn — system should be included
	if !containsAll(p, "You are helpful.") {
		t.Errorf("system prompt not extracted on first turn: %v", p)
	}
}

func TestExtract_OpenAI_ArrayContentParts(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "What is in this image?"},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "What is in this image?") {
		t.Errorf("text part not extracted: %v", p)
	}
	if containsAll(p, "data:image") {
		t.Errorf("image_url should not be extracted: %v", p)
	}
}

func TestExtract_OpenAI_CurrentTurnOnly(t *testing.T) {
	// History before last assistant should not be re-inspected.
	body := `{
		"messages": [
			{"role": "user",      "content": "old secret: sk-oldkey12345678901234"},
			{"role": "assistant", "content": "Got it."},
			{"role": "user",      "content": "new question with no secrets"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "new question") {
		t.Errorf("current turn not extracted: %v", p)
	}
	if containsAll(p, "sk-oldkey") {
		t.Errorf("history should not be re-inspected: %v", p)
	}
}

func TestExtract_OpenAI_SystemExcludedAfterFirstTurn(t *testing.T) {
	// Once there's a prior assistant turn, system prompt has already been sent.
	body := `{
		"messages": [
			{"role": "system",    "content": "You are helpful."},
			{"role": "user",      "content": "turn 1"},
			{"role": "assistant", "content": "response 1"},
			{"role": "user",      "content": "turn 2"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "turn 2") {
		t.Errorf("current user turn not extracted: %v", p)
	}
	if containsAll(p, "You are helpful") {
		t.Errorf("system prompt should not be re-extracted after first turn: %v", p)
	}
}

func TestExtract_OpenAI_LegacyPromptField(t *testing.T) {
	body := `{"prompt": "Complete this: my password is"}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "my password is") {
		t.Errorf("legacy prompt field not extracted: %v", p)
	}
}

func TestExtract_OpenAI_ToolMessage(t *testing.T) {
	// Tool response arrives as a separate message after assistant.
	// It's part of the current turn and should be inspected.
	body := `{
		"messages": [
			{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "function": {"name": "read_file"}}]},
			{"role": "tool",      "content": "file content: api_key=secret123", "tool_call_id": "call_1"},
			{"role": "user",      "content": "thanks"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "api_key=secret123") {
		t.Errorf("tool message content not extracted: %v", p)
	}
}

// ── Anthropic /v1/messages ────────────────────────────────────────────────────

func TestExtract_Anthropic_StringContent(t *testing.T) {
	body := `{
		"system": "You are a coding assistant.",
		"messages": [
			{"role": "user", "content": "Here is my API key: sk-ant-api03-abcdefghijklmnopqrstu"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "sk-ant-api03") {
		t.Errorf("user message not extracted: %v", p)
	}
	if !containsAll(p, "You are a coding assistant") {
		t.Errorf("system prompt not extracted on first turn: %v", p)
	}
}

func TestExtract_Anthropic_ArrayContentBlocks(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "Analyze this"},
				{"type": "image", "source": {"type": "base64", "data": "..."}}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "Analyze this") {
		t.Errorf("text block not extracted: %v", p)
	}
	if containsAll(p, "base64") {
		t.Errorf("image block should not be extracted: %v", p)
	}
}

func TestExtract_Anthropic_ToolResult_StringContent(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "cat /etc/passwd"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": "root:x:0:0:root:/root:/bin/bash"}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "root:x:0:0") {
		t.Errorf("tool_result string content not extracted: %v", p)
	}
}

func TestExtract_Anthropic_ToolResult_BlockContent(t *testing.T) {
	// tool_result content can itself be a content block array.
	body := `{
		"messages": [
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "read"}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": [
					{"type": "text", "text": "password: hunter2"}
				]}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "password: hunter2") {
		t.Errorf("tool_result nested block content not extracted: %v", p)
	}
}

func TestExtract_Anthropic_CurrentTurnOnly(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user",      "content": "old turn with 192.168.1.1"},
			{"role": "assistant", "content": "ok"},
			{"role": "user",      "content": "current turn, no secrets"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "current turn") {
		t.Errorf("current turn not extracted: %v", p)
	}
	if containsAll(p, "192.168.1.1") {
		t.Errorf("old turn IP should not be re-extracted: %v", p)
	}
}

// ── Copilot XML wrapping ──────────────────────────────────────────────────────

func TestExtract_Copilot_WithUserQueryTag(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "<context><file>main.go</file></context><user_query>my ssn is 123-45-6789</user_query>"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "my ssn is 123-45-6789") {
		t.Errorf("user_query content not extracted after XML strip: %v", p)
	}
}

func TestExtract_Copilot_WithoutUserQueryTag(t *testing.T) {
	// The old code skipped this entirely. New code strips XML and inspects.
	body := `{
		"messages": [
			{"role": "user", "content": "<instructions>Be helpful.</instructions><editorContext>fn main() {}</editorContext>my ssn is 123-45-6789"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "my ssn is 123-45-6789") {
		t.Errorf("content after XML strip not extracted: %v", p)
	}
}

func TestExtract_Copilot_XMLOnly_NoUserContent(t *testing.T) {
	// Pure XML context injection with no user text — should return nothing useful
	// for inspection (or at most the text within tags, which has no secrets).
	body := `{
		"messages": [
			{"role": "user", "content": "<context><file>README.md</file><snippet>hello world</snippet></context>"}
		]
	}`
	p := ExtractPrompts([]byte(body))
	// "hello world" is extracted from stripped XML — that's acceptable,
	// the rules won't fire on it. What matters is nothing is silently dropped.
	_ = p
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestExtract_EmptyBody(t *testing.T) {
	if p := ExtractPrompts(nil); len(p) != 0 {
		t.Errorf("nil body: expected empty, got %v", p)
	}
	if p := ExtractPrompts([]byte{}); len(p) != 0 {
		t.Errorf("empty body: expected empty, got %v", p)
	}
}

func TestExtract_InvalidJSON(t *testing.T) {
	if p := ExtractPrompts([]byte("not json")); len(p) != 0 {
		t.Errorf("invalid JSON: expected empty, got %v", p)
	}
}

func TestExtract_Deduplication(t *testing.T) {
	// Same text appears in multiple fields — should appear only once.
	body := `{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "hello"},
				{"type": "text", "text": "hello"}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	count := 0
	for _, s := range p {
		if s == "hello" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 'hello' exactly once, got %d times in %v", count, p)
	}
}

func TestExtract_NoMessages(t *testing.T) {
	body := `{"model": "gpt-4", "stream": true}`
	p := ExtractPrompts([]byte(body))
	if len(p) != 0 {
		t.Errorf("no messages: expected empty, got %v", p)
	}
}

// ── ExtractUserQuery ──────────────────────────────────────────────────────────

func TestUserQuery_PlainOpenAI(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "hello world"}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "hello world" {
		t.Errorf("expected 'hello world', got %q", q)
	}
}

func TestUserQuery_Copilot_WithUserQueryTag(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "<context><file>main.go</file></context><user_query>my actual message</user_query>"}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "my actual message" {
		t.Errorf("expected 'my actual message', got %q", q)
	}
}

func TestUserQuery_Copilot_WithoutUserQueryTag(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user", "content": "<instructions>Be helpful.</instructions>user typed this"}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if !strings.Contains(q, "user typed this") {
		t.Errorf("expected user text after XML strip, got %q", q)
	}
	// Copilot instructions should be stripped
	if strings.Contains(q, "<instructions>") {
		t.Errorf("XML tags should be stripped, got %q", q)
	}
}

func TestUserQuery_CurrentTurnOnly(t *testing.T) {
	body := `{
		"messages": [
			{"role": "user",      "content": "old message"},
			{"role": "assistant", "content": "response"},
			{"role": "user",      "content": "new message"}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "new message" {
		t.Errorf("expected 'new message', got %q", q)
	}
}

func TestUserQuery_SkipsNonUserRoles(t *testing.T) {
	body := `{
		"messages": [
			{"role": "assistant", "content": "previous response"},
			{"role": "tool",      "content": "tool output"},
			{"role": "user",      "content": "user query"}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "user query" {
		t.Errorf("expected only user content, got %q", q)
	}
}

func TestUserQuery_AnthropicMultiBlock_UserQueryInSecondBlock(t *testing.T) {
	// Copilot /v1/messages: context in block 0, <user_query> in block 1.
	// ExtractUserQuery must return only the tag content, not the context.
	body := `{
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "The user's current OS is: macOS I am working in a workspace with the following folders: - /Users/deepakchaudhary/redasq"},
				{"type": "text", "text": "<user_query>123-45-6789</user_query>"}
			]}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "123-45-6789" {
		t.Errorf("expected '123-45-6789', got %q", q)
	}
}

// ── OpenAI Responses API /responses ──────────────────────────────────────────

func TestExtract_ResponsesAPI_InputArray(t *testing.T) {
	body := `{
		"model": "gpt-5-mini",
		"instructions": "You are the GitHub Copilot CLI.",
		"input": [
			{"role": "user", "content": [
				{"type": "input_text", "text": "my api key is key-abc123"}
			]}
		],
		"stream": true
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "my api key is key-abc123") {
		t.Errorf("input_text not extracted: %v", p)
	}
	// First turn — instructions should be included
	if !containsAll(p, "You are the GitHub Copilot CLI") {
		t.Errorf("instructions not extracted on first turn: %v", p)
	}
}

func TestExtract_ResponsesAPI_InstructionsAlwaysScanned(t *testing.T) {
	// Instructions are scanned on every turn — Copilot CLI refreshes file context
	// there on each request, so we must not skip it after the first assistant turn.
	body := `{
		"model": "gpt-5-mini",
		"instructions": "You are the GitHub Copilot CLI.",
		"input": [
			{"role": "user",      "content": [{"type": "input_text", "text": "turn 1"}]},
			{"role": "assistant", "content": [{"type": "text",       "text": "response"}]},
			{"role": "user",      "content": [{"type": "input_text", "text": "turn 2"}]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "turn 2") {
		t.Errorf("current turn not extracted: %v", p)
	}
	if !containsAll(p, "You are the GitHub Copilot CLI") {
		t.Errorf("instructions should be scanned on every turn: %v", p)
	}
	if containsAll(p, "turn 1") {
		t.Errorf("history should not be re-inspected: %v", p)
	}
}

func TestExtract_ResponsesAPI_FunctionCallOutput(t *testing.T) {
	// Copilot CLI swe-agent reads files via tool calls; the file contents come
	// back as function_call_output items and must be scanned for secrets.
	body := `{
		"model": "gpt-5-mini",
		"instructions": "You are the GitHub Copilot CLI.",
		"input": [
			{"role": "user", "content": [{"type": "input_text", "text": "what is the password?"}]},
			{"type": "function_call", "call_id": "call_1", "name": "read_file", "arguments": "{\"path\":\"/app/config.py\"}"},
			{"type": "function_call_output", "call_id": "call_1", "output": "PASSWORD = \"s3cr3tP@ssw0rd\""}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "PASSWORD") {
		t.Errorf("function_call_output not extracted: %v", p)
	}
	if !containsAll(p, "s3cr3tP@ssw0rd") {
		t.Errorf("secret in function_call_output not extracted: %v", p)
	}
	// History before function_call boundary should not be re-scanned.
	if containsAll(p, "what is the password?") {
		t.Errorf("user message before function_call should not be re-extracted: %v", p)
	}
}

func TestExtract_ResponsesAPI_FunctionCallOutputNotRepeatedInHistory(t *testing.T) {
	// On the NEXT turn, the function_call_output is history — must not be re-scanned.
	body := `{
		"model": "gpt-5-mini",
		"instructions": "You are the GitHub Copilot CLI.",
		"input": [
			{"role": "user", "content": [{"type": "input_text", "text": "turn 1"}]},
			{"type": "function_call", "call_id": "call_1", "name": "read_file", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "call_1", "output": "old file content"},
			{"role": "assistant", "content": [{"type": "text", "text": "done"}]},
			{"role": "user", "content": [{"type": "input_text", "text": "turn 2"}]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "turn 2") {
		t.Errorf("current user turn not extracted: %v", p)
	}
	if containsAll(p, "old file content") {
		t.Errorf("function_call_output from history should not be re-scanned: %v", p)
	}
}

func TestExtract_ResponsesAPI_StringInput(t *testing.T) {
	body := `{
		"model": "gpt-5-mini",
		"input": "plain string prompt with secret-value-xyz"
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "secret-value-xyz") {
		t.Errorf("string input not extracted: %v", p)
	}
}

func TestExtract_ResponsesAPI_SkipsNonTextTypes(t *testing.T) {
	body := `{
		"model": "gpt-5-mini",
		"input": [
			{"role": "user", "content": [
				{"type": "input_text",  "text": "user message"},
				{"type": "input_image", "image_url": "data:image/png;base64,..."},
				{"type": "input_file",  "file_id": "file-abc123"}
			]}
		]
	}`
	p := ExtractPrompts([]byte(body))
	if !containsAll(p, "user message") {
		t.Errorf("input_text not extracted: %v", p)
	}
	if containsAll(p, "data:image") || containsAll(p, "file-abc123") {
		t.Errorf("non-text types should not be extracted: %v", p)
	}
}

func TestUserQuery_ResponsesAPI(t *testing.T) {
	body := `{
		"model": "gpt-5-mini",
		"instructions": "You are helpful.",
		"input": [
			{"role": "user", "content": [
				{"type": "input_text", "text": "<context>some file</context><user_query>actual question</user_query>"}
			]}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if q != "actual question" {
		t.Errorf("expected 'actual question', got %q", q)
	}
}

func TestUserQuery_ResponsesAPI_NoUserQueryTag(t *testing.T) {
	body := `{
		"model": "gpt-5-mini",
		"input": [
			{"role": "user", "content": [
				{"type": "input_text", "text": "plain user message"}
			]}
		]
	}`
	q := ExtractUserQuery([]byte(body))
	if !strings.Contains(q, "plain user message") {
		t.Errorf("expected user message, got %q", q)
	}
}

// ── ExtractUsage ─────────────────────────────────────────────────────────────

func TestExtractUsage_ResponsesAPI_CompletedEvent(t *testing.T) {
	// OpenAI Responses API streams a response.completed event with nested usage.
	sse := `data: {"type":"response.output_text.delta","delta":"hello"}
data: {"type":"response.completed","response":{"id":"r1","usage":{"input_tokens":150,"output_tokens":42}}}
`
	in, out := ExtractUsage([]byte(sse))
	if in != 150 {
		t.Errorf("input_tokens: want 150, got %d", in)
	}
	if out != 42 {
		t.Errorf("output_tokens: want 42, got %d", out)
	}
}

func TestExtractUsage_OpenAI_ChatCompletions(t *testing.T) {
	sse := `data: {"choices":[{"delta":{"content":"hi"}}]}
data: {"usage":{"prompt_tokens":100,"completion_tokens":20}}
data: [DONE]
`
	in, out := ExtractUsage([]byte(sse))
	if in != 100 {
		t.Errorf("prompt_tokens: want 100, got %d", in)
	}
	if out != 20 {
		t.Errorf("completion_tokens: want 20, got %d", out)
	}
}

// ── IsStreaming ───────────────────────────────────────────────────────────────

func TestIsStreaming(t *testing.T) {
	if !IsStreaming([]byte(`{"stream": true}`)) {
		t.Error("expected streaming=true")
	}
	if IsStreaming([]byte(`{"stream": false}`)) {
		t.Error("expected streaming=false")
	}
	if IsStreaming([]byte(`{}`)) {
		t.Error("expected streaming=false when field absent")
	}
}

// ── ParseRequest ──────────────────────────────────────────────────────────────

func TestParseRequest_Model(t *testing.T) {
	r := ParseRequest([]byte(`{"model":"claude-sonnet-4-6","stream":true,"messages":[]}`))
	if r.Model != "claude-sonnet-4-6" {
		t.Errorf("model: want claude-sonnet-4-6, got %q", r.Model)
	}
	if !r.Streaming {
		t.Error("expected Streaming=true")
	}
}

func TestParseRequest_SessionID(t *testing.T) {
	body := `{"metadata":{"user_id":"{\"device_id\":\"d1\",\"session_id\":\"sess-abc\"}"},"messages":[]}`
	r := ParseRequest([]byte(body))
	if r.SessionID != "sess-abc" {
		t.Errorf("session_id: want sess-abc, got %q", r.SessionID)
	}
}

func TestParseRequest_Background_Summarize(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"Summarize the following conversation for context"}]}`
	r := ParseRequest([]byte(body))
	if !r.Background {
		t.Error("expected Background=true for summarize prompt")
	}
}

func TestParseRequest_Background_Title(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"Please write a brief title for this conversation"}]}`
	r := ParseRequest([]byte(body))
	if !r.Background {
		t.Error("expected Background=true for title prompt")
	}
}

func TestParseRequest_Background_False(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"what is the capital of France?"}]}`
	r := ParseRequest([]byte(body))
	if r.Background {
		t.Error("expected Background=false for normal user message")
	}
}

func TestParseRequest_Empty(t *testing.T) {
	r := ParseRequest(nil)
	if r.Model != "" || r.Streaming || r.SessionID != "" || len(r.Prompts) != 0 {
		t.Error("empty body should produce zero-value Request")
	}
}

// ── Claude Code (Anthropic /v1/messages) ─────────────────────────────────────

func TestParseRequest_ClaudeCode_FullRequest(t *testing.T) {
	// Typical Claude Code request: system prompt, multi-turn history, current user turn.
	body := `{
		"model": "claude-sonnet-4-6",
		"stream": true,
		"system": "You are Claude Code, a coding assistant.",
		"metadata": {"user_id": "{\"device_id\":\"dev1\",\"session_id\":\"sess-cc-1\"}"},
		"messages": [
			{"role": "user",      "content": "hello"},
			{"role": "assistant", "content": "Hi! How can I help?"},
			{"role": "user",      "content": "read my config file please"}
		]
	}`
	r := ParseRequest([]byte(body))
	if r.Model != "claude-sonnet-4-6" {
		t.Errorf("model: got %q", r.Model)
	}
	if !r.Streaming {
		t.Error("expected Streaming=true")
	}
	if r.SessionID != "sess-cc-1" {
		t.Errorf("session_id: got %q", r.SessionID)
	}
	// System prompt always included in prompts.
	if !containsAll(r.Prompts, "You are Claude Code") {
		t.Errorf("system prompt missing from prompts: %v", r.Prompts)
	}
	// Current turn: only the last user message.
	if !containsAll(r.Prompts, "read my config file please") {
		t.Errorf("current turn missing: %v", r.Prompts)
	}
	// History should not be re-inspected.
	if !containsNone(r.Prompts, "hello", "Hi! How can I help?") {
		t.Errorf("history should not be in prompts: %v", r.Prompts)
	}
	if r.UserQuery != "read my config file please" {
		t.Errorf("user query: got %q", r.UserQuery)
	}
	if r.Background {
		t.Error("Claude Code request should not be Background")
	}
}

func TestParseRequest_ClaudeCode_ToolResult(t *testing.T) {
	// Claude Code sending a tool_result back after a read_file call.
	body := `{
		"model": "claude-sonnet-4-6",
		"stream": true,
		"system": "You are Claude Code.",
		"messages": [
			{"role": "user",      "content": "read server.go"},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "tu1", "name": "read_file", "input": {"path": "server.go"}}]},
			{"role": "user",      "content": [{"type": "tool_result", "tool_use_id": "tu1", "content": "package main\n// secret_key = tok-live-abc123"}]}
		]
	}`
	r := ParseRequest([]byte(body))
	// Tool result content must be inspectable — that's where secrets can leak.
	if !containsAll(r.Prompts, "secret_key") {
		t.Errorf("tool result content not in prompts: %v", r.Prompts)
	}
	// The tool_use block in history should not be re-inspected.
	if !containsNone(r.Prompts, "read server.go") {
		t.Errorf("prior user message should not be in prompts: %v", r.Prompts)
	}
}

// ── VS Code Copilot (OpenAI /v1/chat/completions, XML-wrapped) ───────────────

func TestParseRequest_VSCodeCopilot_UserQueryTag(t *testing.T) {
	// VS Code Copilot wraps context in XML; user's typed message is in <user_query>.
	body := `{
		"model": "gpt-4o",
		"stream": true,
		"messages": [
			{"role": "system", "content": "You are a coding assistant."},
			{"role": "user",   "content": "<context><file>main.go</file></context><user_query>explain this function</user_query>"}
		]
	}`
	r := ParseRequest([]byte(body))
	if r.UserQuery != "explain this function" {
		t.Errorf("user query: want 'explain this function', got %q", r.UserQuery)
	}
	// Full context (including XML-stripped text) should be inspectable.
	if !containsAll(r.Prompts, "explain this function") {
		t.Errorf("user query missing from prompts: %v", r.Prompts)
	}
	if r.Background {
		t.Error("normal Copilot request should not be Background")
	}
}

func TestParseRequest_VSCodeCopilot_BackgroundTitle(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"stream": false,
		"messages": [
			{"role": "user", "content": "Please write a brief title for this conversation about Go interfaces"}
		]
	}`
	r := ParseRequest([]byte(body))
	if !r.Background {
		t.Error("expected Background=true for title generation request")
	}
}

func TestParseRequest_VSCodeCopilot_BackgroundSummarize(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"stream": false,
		"messages": [
			{"role": "user", "content": "Summarize the following conversation for use as context in a future conversation"}
		]
	}`
	r := ParseRequest([]byte(body))
	if !r.Background {
		t.Error("expected Background=true for summarize request")
	}
}

// ── Copilot CLI (OpenAI Responses API /responses) ────────────────────────────

func TestParseRequest_CopilotCLI_FirstTurn(t *testing.T) {
	// First turn: instructions + plain user input string.
	body := `{
		"model": "gpt-4o",
		"stream": true,
		"instructions": "You are a CLI coding assistant. Current file: main.go\npackage main",
		"input": "how do I add a flag?"
	}`
	r := ParseRequest([]byte(body))
	if !containsAll(r.Prompts, "how do I add a flag?") {
		t.Errorf("user input missing from prompts: %v", r.Prompts)
	}
	// Instructions always inspected.
	if !containsAll(r.Prompts, "Current file") {
		t.Errorf("instructions missing from prompts: %v", r.Prompts)
	}
	if r.UserQuery != "how do I add a flag?" {
		t.Errorf("user query: got %q", r.UserQuery)
	}
}

func TestParseRequest_CopilotCLI_FunctionCallOutput(t *testing.T) {
	// Copilot CLI sending a function_call_output (tool result) back to the model.
	body := `{
		"model": "gpt-4o",
		"stream": true,
		"instructions": "You are a CLI coding assistant.",
		"input": [
			{"role": "user",    "type": "message",      "content": [{"type": "input_text", "text": "run ls"}]},
			{"type": "function_call", "name": "bash",   "call_id": "c1"},
			{"type": "function_call_output", "call_id": "c1", "output": "main.go\ngo.mod\nREADME.md"}
		]
	}`
	r := ParseRequest([]byte(body))
	// Tool output is current turn — must be inspectable.
	if !containsAll(r.Prompts, "main.go") {
		t.Errorf("function_call_output missing from prompts: %v", r.Prompts)
	}
	// Prior user message is before the function_call boundary — not re-inspected.
	if !containsNone(r.Prompts, "run ls") {
		t.Errorf("prior user message should not be in prompts: %v", r.Prompts)
	}
}

func TestParseRequest_CopilotCLI_MultiTurn(t *testing.T) {
	// Multi-turn Responses API: current turn is only after last assistant/function_call.
	body := `{
		"model": "gpt-4o",
		"stream": true,
		"instructions": "You are a CLI coding assistant.",
		"input": [
			{"role": "user",      "content": [{"type": "input_text", "text": "first question"}]},
			{"role": "assistant", "content": [{"type": "text",       "text": "first answer"}]},
			{"role": "user",      "content": [{"type": "input_text", "text": "follow up question"}]}
		]
	}`
	r := ParseRequest([]byte(body))
	if !containsAll(r.Prompts, "follow up question") {
		t.Errorf("current turn missing: %v", r.Prompts)
	}
	if !containsNone(r.Prompts, "first question", "first answer") {
		t.Errorf("history should not be in prompts: %v", r.Prompts)
	}
	if r.UserQuery != "follow up question" {
		t.Errorf("user query: got %q", r.UserQuery)
	}
}

// ── FullBody extraction (location-aware history-leak fix) ────────────────────

// TestParseRequest_FullBody_IncludesAnthropicHistory verifies FullBody captures
// every message including those before the last assistant turn — the basis for
// the location-aware history-leak scan.
func TestParseRequest_FullBody_IncludesAnthropicHistory(t *testing.T) {
	body := []byte(`{
		"system": "You are helpful.",
		"messages": [
			{"role": "user",      "content": "older user turn"},
			{"role": "assistant", "content": "older response"},
			{"role": "user",      "content": "current question"}
		]
	}`)
	r := ParseRequest(body)

	// Prompts (current turn) excludes history — block decision is current-turn only.
	if !containsNone(r.Prompts, "older user turn", "older response") {
		t.Errorf("Prompts should NOT contain history: %v", r.Prompts)
	}
	if !containsAll(r.Prompts, "current question") {
		t.Errorf("Prompts should contain current turn: %v", r.Prompts)
	}

	// FullBody includes everything: history + current turn + system.
	for _, want := range []string{"older user turn", "older response", "current question", "You are helpful."} {
		if !containsAll(r.FullBody, want) {
			t.Errorf("FullBody missing %q: %v", want, r.FullBody)
		}
	}
}

// TestParseRequest_FullBody_IncludesResponsesAPIHistory same check for the
// OpenAI Responses API (Copilot CLI shape).
func TestParseRequest_FullBody_IncludesResponsesAPIHistory(t *testing.T) {
	body := []byte(`{
		"instructions": "You are CLI.",
		"input": [
			{"role": "user",      "content": [{"type": "input_text", "text": "older user turn"}]},
			{"role": "assistant", "content": [{"type": "text",       "text": "older response"}]},
			{"role": "user",      "content": [{"type": "input_text", "text": "current question"}]}
		]
	}`)
	r := ParseRequest(body)

	if containsAll(r.Prompts, "older user turn") {
		t.Errorf("Prompts should NOT contain history: %v", r.Prompts)
	}
	if !containsAll(r.Prompts, "current question") {
		t.Errorf("Prompts should contain current turn: %v", r.Prompts)
	}

	for _, want := range []string{"older user turn", "older response", "current question", "You are CLI."} {
		if !containsAll(r.FullBody, want) {
			t.Errorf("FullBody missing %q: %v", want, r.FullBody)
		}
	}
}

// TestParseRequest_FullBody_IncludesToolResultHistory verifies that tool_result
// content from earlier turns is in FullBody. This is the unintentional-leak
// case: agent autonomously fetched sensitive data via a tool, the result lives
// in history, and full-body scan must see it on subsequent turns.
func TestParseRequest_FullBody_IncludesToolResultHistory(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user",      "content": "investigate auth"},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {"path": ".env"}}]},
			{"role": "user",      "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "API_TOKEN=abcdef123"}]},
			{"role": "assistant", "content": "I see the issue."},
			{"role": "user",      "content": "ok try again"}
		]
	}`)
	r := ParseRequest(body)

	// Current turn only has the latest user message.
	if containsAll(r.Prompts, "API_TOKEN=abcdef123") {
		t.Errorf("Prompts (current turn) should NOT contain historical tool_result: %v", r.Prompts)
	}
	// FullBody catches the historical tool_result content.
	if !containsAll(r.FullBody, "API_TOKEN=abcdef123") {
		t.Errorf("FullBody should contain historical tool_result content: %v", r.FullBody)
	}
}
