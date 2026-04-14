#!/usr/bin/env python3
"""
Convert a gitleaks.toml rule database to Go code for inspector/rules.go.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FULL UPDATE WORKFLOW (run from repo root)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Step 1 — Download the latest gitleaks rule database:
    curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/main/config/gitleaks.toml \
         -o /tmp/gitleaks.toml

  Step 2 — Generate rules.go:
    python3 scripts/gen_rules.py /tmp/gitleaks.toml > inspector/rules.go

  Step 3 — Verify it compiles:
    go build ./...

  Step 4 — Run tests:
    go test ./...

That's it. Commit inspector/rules.go.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CUSTOMISING MODE ASSIGNMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Edit MEDIUM_IDS below before running Step 2.

  All rules are ModeBlock — if a pattern fires it found a real credential.

  SeverityHigh   — specific token/key patterns (221 rules by default).
  SeverityMedium — broad/structural patterns (8 rules, see MEDIUM_IDS below).
                   Still blocked, but coloured differently in the UI.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HAND-ROLLED RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The rules at the top of BuiltinRules (ssn, credit-card, http-basic-auth,
etc.) are defined directly in the HAND_ROLLED constant below — they are
not derived from gitleaks. Edit them there if needed.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LICENSE NOTE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

gitleaks is MIT licensed. We use only the rule data (regex patterns and
descriptions), not the library code. No runtime dependency is introduced.
"""

import sys
import tomllib


# ── Mode assignment ───────────────────────────────────────────────────────────
# All rules are ModeBlock — if a pattern fires it found a real credential.
# Broad/structural patterns keep SeverityMedium so the UI left-border colour
# still distinguishes them from specific token rules (SeverityHigh).
MEDIUM_IDS = {
    "generic-api-key",        # matches any `key = value` broadly
    "hashicorp-tf-password",  # matches "password" keyword broadly
    "curl-auth-header",       # curl commands containing real credentials
    "curl-auth-user",         # curl commands containing real credentials
    "kubernetes-secret-yaml", # k8s Secret YAML blocks
    "nuget-config-password",  # XML config with passwords
    "jwt",                    # JSON Web Tokens
    "jwt-base64",             # base64-encoded JWTs
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def go_string(s: str) -> str:
    """Return s as a Go raw string literal, or interpreted string if backtick present."""
    if "`" not in s:
        return f"`{s}`"
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{s}"'


def go_desc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


# ── Hand-rolled rules (kept verbatim, not derived from gitleaks) ──────────────
HAND_ROLLED = r"""	{
		ID:          "ssn",
		Name:        "Social Security Number",
		Description: "US Social Security Number (NNN-NN-NNNN)",
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
		Replacement: "[REDACTED]",
	},
	{
		ID:          "credit-card",
		Name:        "Credit Card Number",
		Description: "Visa / Mastercard / Amex / Discover 16-digit pattern",
		Pattern:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
		Replacement: "[REDACTED]",
		Validate:    luhnCheck,
	},
	{
		ID:          "http-basic-auth",
		Name:        "HTTP Basic Auth Credential",
		Description: "Authorization: Basic <base64> header value",
		Pattern:     regexp.MustCompile(`(?i)Authorization\s*:\s*Basic\s+[a-zA-Z0-9+/]{8,}={0,2}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
		Replacement: "[REDACTED]",
	},
	{
		ID:          "http-bearer-token",
		Name:        "HTTP Bearer Token",
		Description: "Authorization: Bearer <token> header value",
		Pattern:     regexp.MustCompile(`(?i)\bBearer\s+[a-zA-Z0-9\-._~+/]{20,}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
		Replacement: "[REDACTED]",
	},
	{
		// Pattern has two groups: (1) keyword+separator, (2) secret value.
		// Replacement $1[REDACTED] keeps "api_key=" and redacts only the value.
		ID:          "generic-secret",
		Name:        "Generic Secret / Password",
		Description: "Password/secret keyword followed by a value (any separator)",
		Pattern:     regexp.MustCompile(`(?i)(\b(?:access[\s_-]?key|secret[\s_-]?key|api[\s_-]?key|auth[\s_-]?token|bearer|password|passwd|secret)\b\s*(?:=|:)\s*['"]?)([a-zA-Z0-9+/!\-_@#$%^&*]{8,})(['"]?)`),
		Severity:    SeverityMedium,
		Mode:        ModeBlock,
		Replacement: "${1}[REDACTED]${3}",
	},
	{
		ID:          "db-connection-string",
		Name:        "Database Connection String",
		Description: "Database URI with embedded credentials",
		Pattern:     regexp.MustCompile(`(?i)(?:(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|sqlserver|mariadb)://[^:]+:[^@\s]{3,}@[^\s'"` + "`" + `]+|jdbc:oracle:[^:]+:[^/\s]+/[^@\s]{3,}@[^\s'"` + "`" + `]+)`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
		Replacement: "[REDACTED]",
	},
	{
		ID:          "email",
		Name:        "Email Address",
		Description: "Email address",
		Pattern:     regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		Severity:    SeverityLow,
		Mode:        ModeTrack,
		Replacement: "[REDACTED]",
	},
	{
		ID:          "internal-ip",
		Name:        "Internal IP Address",
		Description: "RFC-1918 private IPv4 address",
		Pattern:     regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Severity:    SeverityLow,
		Mode:        ModeTrack,
		Replacement: "[REDACTED]",
	},"""


# ── File header ───────────────────────────────────────────────────────────────
HEADER = """\
package inspector

import "regexp"

type Severity string
type Mode string

const (
\tSeverityHigh   Severity = "high"
\tSeverityMedium Severity = "medium"
\tSeverityLow    Severity = "low"

\tModeTrack Mode = "track"
\tModeBlock Mode = "block"
)

type Rule struct {
\tID          string
\tName        string
\tDescription string
\tPattern     *regexp.Regexp
\tSeverity    Severity
\tMode        Mode
\tReplacement string           // used by RedactText; "$1[REDACTED]" preserves capture group 1
\tValidate    func(string) bool // optional: post-regex validation; nil means accept all matches
}

type Match struct {
\tRuleID   string `json:"rule_id"`
\tRuleName string `json:"rule_name"`
\tSeverity string `json:"severity"`
\tMode     string `json:"mode"`
\tSnippet  string `json:"snippet"`
}

// luhnCheck validates a string of digits using the Luhn algorithm.
func luhnCheck(s string) bool {
\tsum := 0
\tnDigits := len(s)
\tparity := nDigits % 2
\tfor i := 0; i < nDigits; i++ {
\t\td := int(s[i] - '0')
\t\tif i%2 == parity {
\t\t\td *= 2
\t\t\tif d > 9 {
\t\t\t\td -= 9
\t\t\t}
\t\t}
\t\tsum += d
\t}
\treturn sum%10 == 0
}

// BuiltinRules contains hand-rolled rules plus patterns derived from the
// gitleaks rule database (https://github.com/gitleaks/gitleaks, MIT License).
// To update gitleaks patterns, re-run scripts/gen_rules.py against a fresh gitleaks.toml.
var BuiltinRules = []Rule{
"""


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("usage: gen_rules.py <gitleaks.toml>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = tomllib.load(f)

    rules = data.get("rules", [])

    out = [HEADER, HAND_ROLLED]

    converted = skipped = 0
    for r in rules:
        regex = r.get("regex", "")
        if not regex:
            skipped += 1
            continue

        rule_id = r["id"]
        desc = go_desc(r.get("description", rule_id))
        sg = r.get("secretGroup")
        replacement = f"${{{sg}}}[REDACTED]" if sg is not None else "[REDACTED]"
        pat_str = go_string(regex)
        mode = "ModeBlock"
        severity = "SeverityMedium" if rule_id in MEDIUM_IDS else "SeverityHigh"

        out.append(f"""\t{{
\t\tID:          "{rule_id}",
\t\tName:        "{rule_id}",
\t\tDescription: "{desc}",
\t\tPattern:     regexp.MustCompile({pat_str}),
\t\tSeverity:    {severity},
\t\tMode:        {mode},
\t\tReplacement: "{replacement}",
\t}},""")
        converted += 1

    out.append("}\n")

    print("\n".join(out))
    print(f"// Converted: {converted}  Skipped (no regex): {skipped}", file=sys.stderr)


if __name__ == "__main__":
    main()
