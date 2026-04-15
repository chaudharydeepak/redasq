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
		{"AKIAiosfodnn7example1234", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("aws-access-key %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_AnthropicKey(t *testing.T) {
	eng := New()
	// gitleaks anthropic-api-key pattern: sk-ant-api03- + 93 alphanumeric chars + AA
	validKey := "sk-ant-api03-" + strings.Repeat("A", 93) + "AA"
	adminKey := "sk-ant-admin01-" + strings.Repeat("A", 93) + "AA"
	cases := []struct {
		input   string
		blocked bool
	}{
		{validKey, true},
		{"key is " + validKey + " end", true},
		{adminKey, true},
		// too short — only 20 chars after sk-ant-api03- (needs 93+AA)
		{"sk-ant-api03-" + strings.Repeat("a", 20), false},
		// wrong middle segment
		{"sk-ant-" + strings.Repeat("a", 20), false},
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
	// gitleaks openai-api-key: sk-proj/svcacct/admin- + 58 chars + T3BlbkFJ + 58 chars
	validKey := "sk-proj-" + strings.Repeat("A", 58) + "T3BlbkFJ" + strings.Repeat("A", 58)
	cases := []struct {
		input   string
		blocked bool
	}{
		{validKey, true},
		{"key=" + validKey, true},
		// missing T3BlbkFJ marker
		{"sk-proj-" + strings.Repeat("A", 120), false},
		// wrong prefix
		{"sk-" + strings.Repeat("a", 20), false},
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
		// fine-grained PAT — needs 82 word chars (too short here)
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
	// gitleaks private-key requires a full PEM block (header + 64+ bytes of content + footer)
	pemBody := strings.Repeat("A", 64)
	cases := []struct {
		input   string
		blocked bool
	}{
		// full PKCS#8 block
		{"-----BEGIN PRIVATE KEY-----\n" + pemBody + "\n-----END PRIVATE KEY-----", true},
		// full RSA block
		{"-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "\n-----END RSA PRIVATE KEY-----", true},
		// full EC block
		{"-----BEGIN EC PRIVATE KEY-----\n" + pemBody + "\n-----END EC PRIVATE KEY-----", true},
		// full OpenSSH block
		{"-----BEGIN OPENSSH PRIVATE KEY-----\n" + pemBody + "\n-----END OPENSSH PRIVATE KEY-----", true},
		// public key — no match
		{"-----BEGIN PUBLIC KEY-----\n" + pemBody + "\n-----END PUBLIC KEY-----", false},
		// header only, no content/footer — gitleaks pattern requires full block
		{"-----BEGIN RSA PRIVATE KEY-----", false},
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
		{"078-05-1120", true},
		{"my ssn is 900-12-3456", true},
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
		// Visa 16-digit (standard Luhn-valid test number)
		{"card 4532015112830366 exp", true},
		// Mastercard
		{"5425233430109903", true},
		// Amex 15-digit (Luhn-valid test number)
		{"378282246310005", true},
		// Discover
		{"6011000990139424", true},
		// Not a valid Luhn number
		{"4111111111111112", false},
		// Wrong prefix
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

func TestInspect_JWT(t *testing.T) {
	eng := New()
	// gitleaks jwt: ey+17chars . ey+17chars . 10chars + boundary
	// Using alphanumeric-only segments to satisfy [a-zA-Z0-9]{17,} for header
	validJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciJ9.SflKxwRJSMeKKF2QT4fw"
	cases := []struct {
		input   string
		blocked bool
	}{
		{"token: " + validJWT, true},
		{validJWT, true},
		// two segments only — no signature
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0K", false},
		// no eyJ prefix on second segment
		{"eyJhbGciOiJIUzI1NiJ9.notavalidpayload123.SflKxwRJSMeKKF2QT4fw", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("jwt %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

func TestInspect_GenericSecret(t *testing.T) {
	eng := New()
	// generic-secret is now ModeBlock — tested via Inspect
	cases := []struct {
		input   string
		blocked bool
	}{
		{"PASSWORD = SuperSecret1", true},
		{"password: mysecretpass", true},
		{"api_key=abcdef12345678", true},
		{"secret: correct-horse", true},
		{"auth_token=mytoken12345", true},
		// value too short (3 chars — below 8-char minimum)
		{"password=abc", false},
		// no keyword
		{"value=mysecretvalue123", false},
	}
	for _, c := range cases {
		r := eng.Inspect(c.input)
		if r.Blocked != c.blocked {
			t.Errorf("generic-secret %q: blocked=%v want %v", c.input, r.Blocked, c.blocked)
		}
	}
}

// ── Track-mode rules (RedactText) ─────────────────────────────────────────────

func TestRedactText_Email(t *testing.T) {
	eng := New()
	cases := []struct {
		input     string
		wantMatch bool
	}{
		{"contact alice@example.com please", true},
		{"user.name+tag@sub.domain.org", true},
		{"foo@bar.io", true},
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
		{"server at 10.0.0.1", true},
		{"10.255.255.255", true},
		{"host 172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.1.100", true},
		{"192.168.0.1", true},
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
	r := eng.Inspect("ssn 078-05-1120")
	if r.Blocked {
		t.Error("ssn: expected not blocked after switching to track mode")
	}
	// RedactText should now catch it
	redacted, matches := eng.RedactText("ssn 078-05-1120")
	if len(matches) == 0 {
		t.Error("ssn: expected track match after mode switch")
	}
	if strings.Contains(redacted, "078-05-1120") {
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
	body := []byte(`{"messages":[{"role":"user","content":"email me at alice@example.com"}]}`)
	redacted := eng.RedactBodyForForwarding(body)
	if strings.Contains(string(redacted), "alice@example.com") {
		t.Error("RedactBodyForForwarding: email was not redacted in raw body")
	}
}

// ── Agent mode ────────────────────────────────────────────────────────────────

func TestAgentMode_InspectNeverBlocks(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	result := eng.Inspect("my SSN is 078-05-1120")
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
	redacted, matches := eng.RedactText("my SSN is 078-05-1120")
	if strings.Contains(redacted, "078-05-1120") {
		t.Error("AgentMode: RedactText should redact block-mode rules when agent mode is on")
	}
	if len(matches) == 0 {
		t.Error("AgentMode: RedactText should return matches for block-mode rules when agent mode is on")
	}
}

func TestAgentMode_RedactBodyForwardingAppliesBlockRules(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	body := []byte(`{"messages":[{"role":"user","content":"my SSN is 078-05-1120"}]}`)
	redacted := eng.RedactBodyForForwarding(body)
	if strings.Contains(string(redacted), "078-05-1120") {
		t.Error("AgentMode: RedactBodyForForwarding should redact block-mode rules when agent mode is on")
	}
}

func TestAgentMode_OffRestoresNormalBehavior(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true)
	eng.SetAgentMode(false)
	result := eng.Inspect("my SSN is 078-05-1120")
	if !result.Blocked {
		t.Error("AgentMode off: Inspect should block SSN when agent mode is off")
	}
}
