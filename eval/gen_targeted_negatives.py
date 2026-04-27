"""
Generate targeted negative examples for v3 training.

Addresses specific false-positive patterns observed in v2:
  1. x-anthropic-billing-header (appears in every Claude Code prompt going through proxy)
  2. Claude Code / Copilot system prompts ("CRITICAL: Respond with TEXT ONLY...")
  3. Source code with credential-adjacent vocab (Severity, Mode, Track, Block...)
  4. README / knowledge base / docs mentioning passwords/secrets/keys
  5. Test failure / build output listing rule names
  6. Generic conversational dev chat
  7. Tool call envelopes (Read tool with file_path)

Output: targeted_negatives.jsonl
"""
import json
import random
import string
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "targeted_negatives.jsonl"
RANDOM_SEED = 17
random.seed(RANDOM_SEED)

NEGATIVES: list[str] = []


# ── 1. anthropic-billing-header variants (the big one — appears every prompt) ──
def gen_anthropic_billing_headers(n: int) -> list[str]:
    out = []
    for _ in range(n):
        major = random.randint(1, 3)
        minor = random.randint(0, 200)
        patch_a = random.randint(0, 9)
        patch_b = "".join(random.choices("0123456789abcdef", k=3))
        cch = "".join(random.choices("0123456789abcdef", k=5))
        entrypoint = random.choice(["cli", "vscode", "ide", "api"])
        out.append(
            f"x-anthropic-billing-header: cc_version={major}.{minor}.{patch_a}{patch_b}; "
            f"cc_entrypoint={entrypoint}; cch={cch}"
        )
    return out


# ── 2. Claude Code / Copilot system prompts ───────────────────────────────────
SYSTEM_PROMPT_OPENERS = [
    "You are Claude Code, Anthropic's official CLI for Claude.",
    "You are Claude, an AI assistant created by Anthropic.",
    "You are an interactive agent that helps users with software engineering tasks.",
    "You are Copilot, GitHub's AI pair programmer.",
    "You are an AI coding assistant. Help the user with their request.",
    "You are a senior engineer working on the project.",
]

SYSTEM_PROMPT_INSTRUCTIONS = [
    "CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.",
    "Do NOT use Read, Bash, Grep, Glob, Edit, Write, or ANY other tool.",
    "You already have all the context you need in the conversation above.",
    "Tool calls will be REJECTED and will waste your only turn.",
    "Use the tools available to you to assist the user.",
    "IMPORTANT: Assist with authorized security testing, defensive security.",
    "Refuse requests for destructive techniques, DoS attacks, mass targeting.",
    "Always prefer editing existing files to creating new ones.",
    "Be careful not to introduce security vulnerabilities such as command injection.",
    "Use environment variables for storing API keys and secrets.",
    "Implement password complexity requirements per the spec.",
    "Validate input at all system boundaries.",
    "Never log passwords or credentials in plaintext.",
    "Rotate keys every 90 days per security policy.",
]


def gen_system_prompts(n: int) -> list[str]:
    out = []
    for _ in range(n):
        opener = random.choice(SYSTEM_PROMPT_OPENERS)
        n_instructions = random.randint(2, 5)
        instructions = random.sample(SYSTEM_PROMPT_INSTRUCTIONS,
                                     min(n_instructions, len(SYSTEM_PROMPT_INSTRUCTIONS)))
        body = "\n\n" + "\n- ".join([""] + instructions)
        out.append(opener + body)
    return out


# ── 3. Source code with credential-adjacent vocab ────────────────────────────
CODE_TEMPLATES = [
    "type Severity string\nconst (\n\tSeverityHigh Severity = \"high\"\n\tSeverityMedium Severity = \"medium\"\n\tSeverityLow Severity = \"low\"\n)",
    "type Mode string\nconst (\n\tModeTrack Mode = \"track\"\n\tModeBlock Mode = \"block\"\n)",
    "type Rule struct {\n\tID string\n\tName string\n\tDescription string\n\tPattern *regexp.Regexp\n\tSeverity Severity\n\tMode Mode\n\tReplacement string\n}",
    "func ExtractUserQuery(body []byte) string {\n\tif len(body) == 0 { return \"\" }\n\tvar envelope struct {\n\t\tMessages []struct{}\n\t}\n\tjson.Unmarshal(body, &envelope)\n\treturn \"\"\n}",
    "package proxy\n\nimport (\n\t\"crypto/tls\"\n\t\"net/http\"\n\t\"github.com/chaudharydeepak/redasq/inspector\"\n)",
    "// extractTelemetryInfo parses the telemetry payload\nfunc extractTelemetryInfo(body []byte) string {\n\treturn \"telemetry\"\n}",
    "func RedactBodyForForwarding(body []byte) []byte {\n\treturn body // placeholder\n}",
    "import { ParseRequest, ExtractPrompts } from '@/lib/inspector';\nimport { Severity, Mode } from '@/types';",
    "const InspectAndStore = async (req: Request) => {\n\tconst result = await inspect(req.body);\n\treturn store.save(result);\n};",
    "// SavePrompt persists the inspected prompt with status and matches.\nfunc SavePrompt(p Prompt) error {\n\treturn db.Exec(query, p.Status, p.Matches)\n}",
    "type AuthConfig struct {\n\tEnabled bool\n\tProvider string\n\tCallbackURL string\n}\n// No actual secrets here, just config types.",
    "test('password validation works', () => {\n\texpect(validatePassword('short')).toBe(false);\n\texpect(validatePassword('LongEnough123!')).toBe(true);\n});",
    "describe('credential rotation', () => {\n\tit('rotates keys every 90 days', () => {});\n});",
]


def gen_code_snippets(n: int) -> list[str]:
    out = []
    for _ in range(n):
        out.append(random.choice(CODE_TEMPLATES))
    return out


# ── 4. README / docs mentioning passwords/secrets/keys ───────────────────────
DOC_TEMPLATES = [
    "# Prompt Guard\n\nA lightweight HTTPS MITM proxy that intercepts prompts sent to AI coding assistants and APIs — blocking or redacting sensitive data before it leaves your machine.",
    "# redasq\n\nLocal HTTPS MITM proxy intercepting AI coding assistant traffic. Inspects, redacts, or blocks sensitive data before it leaves the machine.",
    "## Features\n\n- 230 built-in detection rules (gitleaks + custom)\n- Live dashboard with real-time prompt monitoring\n- SQLite audit log\n- Block or redact modes per rule",
    "## Why\n\nAI tools like GitHub Copilot, ChatGPT, and Claude receive your full editor context. That context routinely contains API keys, passwords, database credentials, SSNs, and internal IPs.",
    "## Rules\n\n| Mode | Behaviour |\n|---|---|\n| Block | Request rejected; nothing forwarded to the AI |\n| Track | Sensitive value replaced with [REDACTED]; sanitised prompt forwarded and logged |",
    "## Built-in detection\n\n- AWS access keys (AKIA...)\n- GitHub PATs (ghp_, gho_, ghs_)\n- Anthropic keys (sk-ant-api03-...)\n- OpenAI keys (sk-...)\n- Generic credentials (passwords, tokens)",
    "## Configuration\n\nSee ~/.redasq/rules.json to customize rule modes. Changes take effect immediately without restart.",
    "## Architecture\n\nredasq sits as a transparent HTTPS proxy. Set HTTP_PROXY and HTTPS_PROXY env vars to route traffic through it.",
    "Implementation note: passwords stored hashed via argon2id, never in plaintext. Token rotation is enforced at the API layer.",
    "Security policy: API keys must be rotated every 90 days. Database passwords rotate quarterly. SSH keys are managed via vault.",
    "# Prompt Guard knowledge base\n# DO NOT COMMIT — session context file\n\n## What it is\nLocal HTTPS MITM proxy intercepting AI coding assistant traffic.",
]


def gen_docs(n: int) -> list[str]:
    out = []
    for _ in range(n):
        out.append(random.choice(DOC_TEMPLATES))
    return out


# ── 5. Test failure / build output ────────────────────────────────────────────
def gen_test_output(n: int) -> list[str]:
    rule_names = [
        "1password-secret-key", "1password-service-account-token",
        "adafruit-api-key", "adobe-client-id", "adobe-client-secret",
        "age-secret-key", "airtable-api-key", "alibaba-access-key-id",
        "anthropic-api-key", "artifactory-api-key", "asana-client-id",
        "asana-client-secret", "atlassian-api-token", "aws-access-token",
        "azure-ad-client-secret", "beamer-api-token", "bittrex-api-key",
        "bitbucket-client-id", "bitbucket-client-secret",
        "clojars-api-token", "codecov-access-token", "coinbase-access-token",
        "confluent-access-token", "contentful-delivery-api-token",
        "databricks-api-token", "datadog-access-token", "definednetworking-api-token",
        "digitalocean-pat", "discord-api-token", "doppler-api-token",
    ]
    out = []
    for _ in range(n):
        n_lines = random.randint(5, 20)
        sampled = random.sample(rule_names, min(n_lines, len(rule_names)))
        lines = [f"{rn}: go: no go files listed" for rn in sampled]
        out.append("Failed: " + " ".join(lines))
        # Also a passing variant
        out.append("Passed: " + " ".join([f"{rn}: ok" for rn in sampled[:5]]))
    return out


# ── 6. Generic dev conversation ───────────────────────────────────────────────
DEV_CHAT = [
    "running - is there a tool that can generate more variety of test data?",
    "lets fix model first - include both positive and negative behaviors",
    "we need to install gliner and dependencies first",
    "the eval script is broken, let me fix it",
    "i think the regex pattern is too broad",
    "checking the logs for the failed deploy",
    "vscode shows the file but it's empty",
    "running on macos with python 3.11",
    "uploaded the model and started training",
    "the gpu instance is up and running",
    "lets try with a higher learning rate next time",
    "the loss is not decreasing as expected",
    "model checkpoint failed because disk is full",
    "what is the difference between copilot cli and claude cli",
    "the dashboard shows no tables yet",
    "rebuilding and restarting the proxy",
    "let me check the config file again",
    "git push is failing — looks like a permission thing",
    "the build worked but tests are flaky",
    "trying to figure out why the request is timing out",
    "lets refactor the inspector engine module",
    "we should add more negative test cases",
    "the function ExtractPrompts is doing too much",
    "yeah lets do that, sounds good",
    "ok cool, ship it",
    "actually i think we should try the other approach first",
    "can you look at the disagreements file?",
    "what does the eval show?",
    "i'm going to download the model now",
    "lets run it against the full database",
]


# ── 7. Tool call envelopes ───────────────────────────────────────────────────
def gen_tool_calls(n: int) -> list[str]:
    files = [
        "/Users/dev/redasq/main.go",
        "/Users/dev/redasq/inspector/rules.go",
        "/Users/dev/redasq/proxy/proxy.go",
        "/Users/dev/redasq/web/web.go",
        "/Users/dev/redasq/store/store.go",
        "/home/user/.github/workflows/release.yml",
        "/etc/nginx/conf.d/proxy.conf",
        "~/redasq/eval/train_distilbert.py",
    ]
    commands = ["sqlite3 ~/.redasq/redasq.db", "ls -la", "cat README.md",
                "grep -r 'TODO' .", "find . -name '*.go'"]
    out = []
    for _ in range(n):
        if random.random() < 0.5:
            f = random.choice(files)
            out.append(f'Called the Read tool with the following input: {{"file_path":"{f}"}}')
        else:
            c = random.choice(commands)
            out.append(f'Called the Bash tool with the following input: {{"command":"{c}"}}')
    return out


# ── 8. Long prompt with billing header + system prompt + user message ────────
# This combo is what redasq actually sees on every Claude Code request.
def gen_realistic_long_prompts(n: int) -> list[str]:
    out = []
    billing = gen_anthropic_billing_headers(n)
    sys = gen_system_prompts(n)
    user_messages = [
        "lets refactor the inspector engine",
        "what does this function do?",
        "why is the build failing?",
        "can you check the config?",
        "i need to add a new rule",
        "how do i deploy this?",
        "check the logs",
    ]
    for i in range(n):
        out.append(
            f"{billing[i]}\n\n{sys[i]}\n\nUser message: {random.choice(user_messages)}"
        )
    return out


def main() -> None:
    print("Generating targeted negatives based on observed v2 false positives...\n")

    # Heavy on the patterns that fired most.
    NEGATIVES.extend(gen_anthropic_billing_headers(2000))
    NEGATIVES.extend(gen_system_prompts(800))
    NEGATIVES.extend(gen_realistic_long_prompts(800))   # combo: billing + sys + user
    NEGATIVES.extend(gen_code_snippets(600))
    NEGATIVES.extend(gen_docs(400))
    NEGATIVES.extend(gen_test_output(200))
    NEGATIVES.extend(DEV_CHAT * 8)  # repeat for emphasis
    NEGATIVES.extend(gen_tool_calls(400))

    # Deduplicate
    seen = set()
    deduped = []
    for text in NEGATIVES:
        if text in seen:
            continue
        seen.add(text)
        deduped.append({"text": text, "labels": []})

    random.shuffle(deduped)
    with OUTPUT_PATH.open("w") as f:
        for ex in deduped:
            f.write(json.dumps(ex) + "\n")

    print(f"Wrote {len(deduped)} targeted negatives → {OUTPUT_PATH}")
    print(f"  anthropic-billing-headers (heavy emphasis)")
    print(f"  system prompts")
    print(f"  long prompts combining billing + system + user")
    print(f"  code snippets")
    print(f"  documentation")
    print(f"  test output / build logs")
    print(f"  dev conversation")
    print(f"  tool call envelopes")


if __name__ == "__main__":
    main()
