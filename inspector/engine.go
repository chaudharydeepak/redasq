package inspector

import "sync"

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
// In agent mode all rules are applied regardless of their configured mode.
func (e *Engine) RedactBodyForForwarding(body []byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

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
