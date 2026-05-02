package inspector

import (
	"bytes"
	"encoding/json"
	"sync"
)

// textContentFields names JSON keys whose string values are user- or
// assistant-generated text content — the only places redasq should ever
// rewrite values when forwarding a request. Anything outside this allowlist
// (signatures, opaque IDs, tool names, type/role discriminators, status
// strings, model identifiers, …) is API-protocol metadata and gets passed
// through untouched, so a regex that happens to match a metadata-shaped
// string can't corrupt the body and break the upstream API call.
//
// Cross-vendor coverage: Anthropic /v1/messages, OpenAI /v1/chat/completions,
// OpenAI Responses /v1/responses (Copilot CLI), and OpenAI-compatible
// variants (Copilot VS Code).
//
// Field origins:
//   - content       Anthropic + OpenAI message content (string form)
//   - text          Anthropic content blocks, OpenAI content parts, Responses API content items
//   - thinking      Anthropic extended-thinking block reasoning text
//   - tool_result   Anthropic — string form, plus the nested-block recursion target
//   - output        OpenAI Responses function_call_output payload
//   - arguments     OpenAI / Responses tool/function call arguments
//   - system        Anthropic top-level system prompt
//   - instructions  OpenAI Responses top-level instructions
//   - input         OpenAI Responses top-level input (string form)
//   - prompt        Legacy /v1/completions prompt field
var textContentFields = map[string]bool{
	"content":      true,
	"text":         true,
	"thinking":     true,
	"tool_result":  true,
	"output":       true,
	"arguments":    true,
	"system":       true,
	"instructions": true,
	"input":        true,
	"prompt":       true,
}

// Result is the outcome of inspecting a prompt.
type Result struct {
	Matches []Match
	Blocked bool
}

// Engine runs all active rules against text and returns matches.
type Engine struct {
	mu        sync.RWMutex
	rules     []Rule
	agentMode bool
}

// SetAgentMode enables or disables agent mode. In agent mode all traffic is
// redacted regardless of per-rule mode — nothing is blocked.
func (e *Engine) SetAgentMode(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.agentMode = on
}

// AgentMode returns whether agent mode is currently active.
func (e *Engine) AgentMode() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.agentMode
}

func New() *Engine {
	rules := make([]Rule, len(BuiltinRules))
	copy(rules, BuiltinRules)
	return &Engine{rules: rules}
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// AddRule appends a custom rule to the engine.
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// SetSeverity updates the severity of a rule by ID. Returns false if not found.
func (e *Engine) SetSeverity(ruleID string, sev Severity) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == ruleID {
			e.rules[i].Severity = sev
			return true
		}
	}
	return false
}

// SetMode updates the mode of a rule by ID. Returns false if rule not found.
func (e *Engine) SetMode(ruleID string, mode Mode) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == ruleID {
			e.rules[i].Mode = mode
			return true
		}
	}
	return false
}

// RedactText replaces rule matches in the extracted prompt text.
// In agent mode all rules are applied regardless of their configured mode.
// Returns the redacted text and one Match per rule that fired.
func (e *Engine) RedactText(text string) (string, []Match) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := text
	var matches []Match
	for _, rule := range e.rules {
		if !e.agentMode && rule.Mode != ModeTrack {
			continue
		}
		// Find first valid match (applying optional post-regex validator).
		var loc []int
		if rule.Validate != nil {
			for _, l := range rule.Pattern.FindAllStringIndex(result, -1) {
				if rule.Validate(result[l[0]:l[1]]) {
					loc = l
					break
				}
			}
		} else {
			loc = rule.Pattern.FindStringIndex(result)
		}
		if loc == nil {
			continue
		}
		snipStart := loc[0] - 20
		if snipStart < 0 {
			snipStart = 0
		}
		snipEnd := loc[1] + 20
		if snipEnd > len(result) {
			snipEnd = len(result)
		}
		snippet := result[snipStart:snipEnd]
		if snipStart > 0 {
			snippet = "…" + snippet
		}
		if snipEnd < len(result) {
			snippet = snippet + "…"
		}
		if rule.Validate != nil {
			result = rule.Pattern.ReplaceAllStringFunc(result, func(m string) string {
				if rule.Validate(m) {
					return rule.Replacement
				}
				return m
			})
		} else {
			result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
		}
		matches = append(matches, Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: string(rule.Severity),
			Mode:     string(rule.Mode),
			Snippet:  snippet,
		})
	}
	return result, matches
}

// RedactBodyForForwarding applies track-mode replacements to the raw request body.
// For JSON bodies it operates only on text-content fields (see textContentFields)
// so the JSON structure and protocol metadata are never corrupted. Falls back to
// plain string replacement for non-JSON bodies. In agent mode all rules are
// applied regardless of their configured mode.
func (e *Engine) RedactBodyForForwarding(body []byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if json.Valid(body) {
		var v interface{}
		if err := json.Unmarshal(body, &v); err == nil {
			v = e.redactJSONValue(v, "")
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err == nil {
				return bytes.TrimRight(buf.Bytes(), "\n")
			}
		}
	}

	// Non-JSON fallback (plain text, YAML, etc.) — no field context, apply
	// replacements directly. The textContentFields filter only applies to JSON.
	s := string(body)
	for _, rule := range e.rules {
		if e.agentMode || rule.Mode == ModeTrack {
			if rule.Validate != nil {
				s = rule.Pattern.ReplaceAllStringFunc(s, func(m string) string {
					if rule.Validate(m) {
						return rule.Replacement
					}
					return m
				})
			} else {
				s = rule.Pattern.ReplaceAllString(s, rule.Replacement)
			}
		}
	}
	return []byte(s)
}

// RedactBlockMatchesFromBody walks the JSON body and applies block-mode rule
// patterns to text-content fields only. Used in the location-aware history-leak
// fix: when a block-mode value sits in conversation history (but not the
// current turn), the proxy silently scrubs it from the outbound body so the
// value doesn't leak to upstream — without raising a fresh dashboard alarm
// or blocking the request entirely.
//
// Falls back to plain string replacement for non-JSON bodies. Agent mode is
// not consulted here — block-mode patterns are applied unconditionally
// because we've already determined a block-mode rule fired in history; we're
// just choosing to scrub instead of block to preserve session usability.
func (e *Engine) RedactBlockMatchesFromBody(body []byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if json.Valid(body) {
		var v interface{}
		if err := json.Unmarshal(body, &v); err == nil {
			v = e.redactBlockJSONValue(v, "")
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err == nil {
				return bytes.TrimRight(buf.Bytes(), "\n")
			}
		}
	}

	s := string(body)
	for _, rule := range e.rules {
		if rule.Mode != ModeBlock {
			continue
		}
		if rule.Validate != nil {
			s = rule.Pattern.ReplaceAllStringFunc(s, func(m string) string {
				if rule.Validate(m) {
					return rule.Replacement
				}
				return m
			})
		} else {
			s = rule.Pattern.ReplaceAllString(s, rule.Replacement)
		}
	}
	return []byte(s)
}

// redactBlockJSONValue mirrors redactJSONValue but applies BLOCK-mode rules
// rather than TRACK-mode. Used by RedactBlockMatchesFromBody. parentField is
// the name of the JSON object key that led to this value (or the parent
// container's key when traversing array elements). Mutation only happens for
// strings whose parentField is in textContentFields.
func (e *Engine) redactBlockJSONValue(v interface{}, parentField string) interface{} {
	switch val := v.(type) {
	case string:
		if !textContentFields[parentField] {
			return val
		}
		for _, rule := range e.rules {
			if rule.Mode != ModeBlock {
				continue
			}
			if rule.Validate != nil {
				val = rule.Pattern.ReplaceAllStringFunc(val, func(m string) string {
					if rule.Validate(m) {
						return rule.Replacement
					}
					return m
				})
			} else {
				val = rule.Pattern.ReplaceAllString(val, rule.Replacement)
			}
		}
		return val
	case map[string]interface{}:
		for k, v2 := range val {
			val[k] = e.redactBlockJSONValue(v2, k)
		}
		return val
	case []interface{}:
		for i, v2 := range val {
			val[i] = e.redactBlockJSONValue(v2, parentField)
		}
		return val
	default:
		return v
	}
}

// redactJSONValue recursively walks a decoded JSON value and applies redaction
// rules to text-content string leaves only. parentField is the name of the
// JSON object key that led to this value (or the parent container's key when
// traversing array elements); see textContentFields for the allowlist.
func (e *Engine) redactJSONValue(v interface{}, parentField string) interface{} {
	switch val := v.(type) {
	case string:
		if !textContentFields[parentField] {
			return val
		}
		for _, rule := range e.rules {
			if !e.agentMode && rule.Mode != ModeTrack {
				continue
			}
			if rule.Validate != nil {
				val = rule.Pattern.ReplaceAllStringFunc(val, func(m string) string {
					if rule.Validate(m) {
						return rule.Replacement
					}
					return m
				})
			} else {
				val = rule.Pattern.ReplaceAllString(val, rule.Replacement)
			}
		}
		return val
	case map[string]interface{}:
		for k, v2 := range val {
			val[k] = e.redactJSONValue(v2, k)
		}
		return val
	case []interface{}:
		for i, v2 := range val {
			val[i] = e.redactJSONValue(v2, parentField)
		}
		return val
	default:
		return v
	}
}

func (e *Engine) Inspect(text string) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.agentMode {
		return Result{} // agent mode: never block, redaction handled separately
	}

	var result Result
	for _, rule := range e.rules {
		if rule.Mode != ModeBlock {
			continue
		}
		var locs []int
		if rule.Validate != nil {
			for _, l := range rule.Pattern.FindAllStringIndex(text, -1) {
				if rule.Validate(text[l[0]:l[1]]) {
					locs = l
					break
				}
			}
		} else {
			locs = rule.Pattern.FindStringIndex(text)
		}
		if locs == nil {
			continue
		}
		start, end := locs[0], locs[1]
		snipStart := start - 20
		if snipStart < 0 {
			snipStart = 0
		}
		snipEnd := end + 20
		if snipEnd > len(text) {
			snipEnd = len(text)
		}
		snippet := text[snipStart:snipEnd]
		if snipStart > 0 {
			snippet = "…" + snippet
		}
		if snipEnd < len(text) {
			snippet = snippet + "…"
		}
		result.Matches = append(result.Matches, Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: string(rule.Severity),
			Mode:     string(rule.Mode),
			Snippet:  snippet,
		})
		if rule.Mode == ModeBlock {
			result.Blocked = true
		}
	}
	return result
}
