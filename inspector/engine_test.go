package inspector

import (
	"strings"
	"testing"
)

// ── Block-mode rules (Inspect) ────────────────────────────────────────────────

func TestInspect_AWSAccessKey(t *testing.T) {
	eng := New()
	cases := []struct {
		input   string
		blocked bool
	}{
		// real 20-char AWS key: AKIA + 16 uppercase alphanumeric
		{"my key is AKIAIOSFODNN7EXAMPLE", true},
		{"AKIAIOSFODNN7EXAMPLE something", true},
		// too short — only 15 chars after AKIA
		{"AKIAIOSFODNN7EXAMPL", false},
		// wrong prefix
		{"BKIAIOSFODNN7EXAMPLE", false},
		// lowercase chars after AKIA — pattern requires [0-9A-Z] only
		{"AKIAiosfodnn7exampl", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("aws-access-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_AWSSecretKey(t *testing.T) {
	eng := New()
	// Pattern: (?i)aws.{0,20}secret.{0,20}['"]?([0-9a-zA-Z/+]{40})['"]?
	// 40-char base64-ish value
	secret40 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN" // exactly 40 chars
	cases := []struct {
		input   string
		blocked bool
	}{
		{"aws secret " + secret40, true},
		{"AWS_SECRET_KEY=" + secret40, true},
		{"aws secret key is " + secret40, true},
		// value only 39 chars — should not match
		{"aws secret key=" + secret40[:39], false},
		// no "aws" context
		{"secret=" + secret40, false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("aws-secret-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_AnthropicKey(t *testing.T) {
	eng := New()
	// Pattern: sk-ant-[a-zA-Z0-9\-_]{20,}
	// Note: openai-key (sk-[...]{20,}) overlaps — anything starting with sk- and
	// long enough will also be blocked by that rule. Negative cases must avoid sk-.
	cases := []struct {
		input   string
		blocked bool
	}{
		{"key: sk-ant-api03-abcdefghijklmnopqrstu", true},
		{"sk-ant-" + strings.Repeat("a", 20), true},
		// only 9 chars after sk-ant- (13 after sk-) — too short for both rules
		{"sk-ant-abc123456", false},
		// wrong prefix, doesn't start with sk- so openai-key won't fire either
		{"ak-ant-" + strings.Repeat("a", 20), false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("anthropic-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_OpenAIKey(t *testing.T) {
	eng := New()
	// Pattern: sk-[a-zA-Z0-9\-_]{20,}
	// Note: anthropic keys (sk-ant-...) also match this pattern — both rules fire.
	cases := []struct {
		input   string
		blocked bool
	}{
		{"sk-proj-" + strings.Repeat("a", 20), true},
		{"sk-" + strings.Repeat("a", 20), true},
		// only 19 chars after sk- — should not match
		{"sk-" + strings.Repeat("a", 19), false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("openai-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_GitHubToken(t *testing.T) {
	eng := New()
	// Pattern: gh[pousr]_[a-zA-Z0-9]{36,}
	token36 := strings.Repeat("a", 36)
	cases := []struct {
		input   string
		blocked bool
	}{
		{"ghp_" + token36, true},  // personal access token
		{"gho_" + token36, true},  // oauth token
		{"ghu_" + token36, true},  // user-to-server token
		{"ghs_" + token36, true},  // server-to-server token
		{"ghr_" + token36, true},  // refresh token
		// only 35 chars — should not match
		{"ghp_" + strings.Repeat("a", 35), false},
		// invalid prefix char
		{"ghx_" + token36, false},
		// classic PAT (no prefix) — not matched by this pattern
		{"github_pat_" + token36, false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("github-token %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_PrivateKey(t *testing.T) {
	eng := New()
	cases := []struct {
		input   string
		blocked bool
	}{
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"-----BEGIN EC PRIVATE KEY-----", true},
		{"-----BEGIN PRIVATE KEY-----", true},       // PKCS#8
		{"-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"-----BEGIN PUBLIC KEY-----", false},        // public key — no match
		{"BEGIN RSA PRIVATE KEY", false},             // missing dashes
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("private-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_SSN(t *testing.T) {
	eng := New()
	cases := []struct {
		input   string
		blocked bool
	}{
		{"ssn: 123-45-6789", true},
		{"000-00-0001", true},
		{"999-99-9999", true},
		// phone number format — 3-3-4, not 3-2-4
		{"123-456-7890", false},
		// missing boundary (part of longer number)
		{"1234-45-6789", false},
		{"123-45-67890", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("ssn %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_CreditCard(t *testing.T) {
	eng := New()
	cases := []struct {
		input   string
		blocked bool
	}{
		// Visa 16-digit (standard test number)
		{"card 4111111111111111 exp", true},
		// Visa 13-digit
		{"4222222222222", true},
		// Mastercard (51-55 prefix, 16 digits)
		{"5500000000000004", true},
		{"5105105105105100", true},
		// Amex (34 or 37 prefix, 15 digits)
		{"378282246310005", true},
		{"371449635398431", true},
		// Discover (6011 or 65 prefix, 16 digits)
		{"6011111111111117", true},
		{"6500000000000002", true},
		// Not a valid card prefix
		{"1234567890123456", false},
		// Too short
		{"411111111111", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("credit-card %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

// ── Track-mode rules (RedactText) ─────────────────────────────────────────────

func TestRedactText_JWT(t *testing.T) {
	eng := New()
	// Minimal valid JWT shape: header.payload.signature, header+payload must start with eyJ
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	redacted, matches := eng.RedactText("token: " + jwt)
	if len(matches) == 0 {
		t.Error("jwt: expected match, got none")
	}
	if strings.Contains(redacted, jwt) {
		t.Error("jwt: token was not redacted")
	}
	// non-JWT — two base64 segments but no eyJ prefix on payload
	_, matches2 := eng.RedactText("not.a.jwt")
	if len(matches2) != 0 {
		t.Error("jwt: false positive on 'not.a.jwt'")
	}
}

func TestRedactText_GenericSecret(t *testing.T) {
	eng := New()
	cases := []struct {
		input     string
		wantMatch bool
	}{
		{"api_key=mysecretvalue123", true},
		{"password: hunter22", true},          // 8-char value, colon separator
		{"secret: myS3cr3tVal", true},         // colon separator
		{"bearer: mytoken1234", true},         // colon separator
		{"auth_token=abcdefgh", true},         // 8-char value
		// value too short (3 chars)
		{"password=abc", false},
		// no keyword
		{"value=mysecretvalue123", false},
	}
	for _, c := range cases {
		_, matches := eng.RedactText(c.input)
		found := false
		for _, m := range matches {
			if m.RuleID == "generic-secret" {
				found = true
			}
		}
		if found != c.wantMatch {
			t.Errorf("generic-secret %q: matched=%v want %v", c.input, found, c.wantMatch)
		}
	}
}

func TestRedactText_Email(t *testing.T) {
	eng := New()
	cases := []struct {
		input     string
		wantMatch bool
	}{
		{"contact user@example.com please", true},
		{"john.doe+tag@company.co.uk", true},
		{"first.last@sub.domain.org", true},
		// no @ sign
		{"notanemail.com", false},
		// missing TLD
		{"user@host", false},
	}
	for _, c := range cases {
		redacted, matches := eng.RedactText(c.input)
		found := false
		for _, m := range matches {
			if m.RuleID == "email" {
				found = true
			}
		}
		if found != c.wantMatch {
			t.Errorf("email %q: matched=%v want %v", c.input, found, c.wantMatch)
		}
		if c.wantMatch && strings.Contains(redacted, "@") {
			t.Errorf("email %q: email was not redacted, got: %s", c.input, redacted)
		}
	}
}

func TestRedactText_InternalIP(t *testing.T) {
	eng := New()
	cases := []struct {
		input     string
		wantMatch bool
	}{
		// 10.x.x.x
		{"server at 10.0.0.1", true},
		{"10.255.255.255", true},
		// 172.16-31.x.x
		{"host 172.16.0.1", true},
		{"172.31.255.255", true},
		// 192.168.x.x
		{"192.168.1.1", true},
		{"192.168.0.254", true},
		// public IPs — not RFC-1918
		{"8.8.8.8", false},
		{"172.15.0.1", false},  // 172.15 is not private
		{"172.32.0.1", false},  // 172.32 is not private
		{"192.169.1.1", false}, // 192.169 is not private
	}
	for _, c := range cases {
		_, matches := eng.RedactText(c.input)
		found := false
		for _, m := range matches {
			if m.RuleID == "internal-ip" {
				found = true
			}
		}
		if found != c.wantMatch {
			t.Errorf("internal-ip %q: matched=%v want %v", c.input, found, c.wantMatch)
		}
	}
}

// ── SetMode / mode switching ──────────────────────────────────────────────────

func TestSetMode_BlockToTrack(t *testing.T) {
	eng := New()
	// SSN is block by default — switching to track should stop Inspect from blocking
	eng.SetMode("ssn", ModeTrack)
	r := eng.Inspect("ssn 123-45-6789")
	if r.Blocked {
		t.Error("ssn: expected not blocked after switching to track mode")
	}
	// RedactText should now catch it
	redacted, matches := eng.RedactText("ssn 123-45-6789")
	if len(matches) == 0 {
		t.Error("ssn: expected track match after mode switch")
	}
	if strings.Contains(redacted, "123-45-6789") {
		t.Error("ssn: value was not redacted after mode switch")
	}
}

func TestSetMode_UnknownRule(t *testing.T) {
	eng := New()
	ok := eng.SetMode("nonexistent-rule", ModeBlock)
	if ok {
		t.Error("SetMode: expected false for unknown rule ID")
	}
}

// ── RedactBodyForForwarding ───────────────────────────────────────────────────

func TestRedactBodyForForwarding_Email(t *testing.T) {
	eng := New()
	body := []byte(`{"messages":[{"role":"user","content":"email me at secret@corp.com"}]}`)
	redacted := eng.RedactBodyForForwarding(body)
	if strings.Contains(string(redacted), "secret@corp.com") {
		t.Error("RedactBodyForForwarding: email was not redacted in raw body")
	}
}

func TestAgentMode_InspectNeverBlocks(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	result := eng.Inspect("my SSN is 123-45-6789")
	if result.Blocked {
		t.Error("AgentMode: Inspect should never block when agent mode is on")
	}
	if len(result.Matches) > 0 {
		t.Error("AgentMode: Inspect should return no matches when agent mode is on")
	}
}

func TestAgentMode_RedactTextAppliesBlockRules(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	redacted, matches := eng.RedactText("my SSN is 123-45-6789")
	if strings.Contains(redacted, "123-45-6789") {
		t.Error("AgentMode: RedactText should redact block-mode rules when agent mode is on")
	}
	if len(matches) == 0 {
		t.Error("AgentMode: RedactText should return matches for block-mode rules when agent mode is on")
	}
}

func TestAgentMode_RedactBodyForwardingAppliesBlockRules(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	body := []byte(`{"messages":[{"role":"user","content":"my SSN is 123-45-6789"}]}`)
	redacted := eng.RedactBodyForForwarding(body)
	if strings.Contains(string(redacted), "123-45-6789") {
		t.Error("AgentMode: RedactBodyForForwarding should redact block-mode rules when agent mode is on")
	}
}

func TestAgentMode_OffRestoresNormalBehavior(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	eng.SetAgentMode(false)
	result := eng.Inspect("my SSN is 123-45-6789")
	if !result.Blocked {
		t.Error("AgentMode off: Inspect should block SSN when agent mode is off")
	}
}
