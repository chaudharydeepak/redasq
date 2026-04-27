"""
Build a focused evaluation set for v5 that explicitly tests the regressions
we noticed in production conversations PLUS regression coverage so existing
positive cases stay correct.

Two asks for v5:
  1. FP suppression — meta-discussion of classification, CLI-tool mentions,
     short conversational acks, file/path references must NOT fire any label.
     These are the prompts that frustrated the user during this debugging
     session (rows 4724, 4729, and the 4728-style Copilot-CLI wrapped ones).
  2. Regression — concrete credentials, PEM bodies, hostnames-with-passwords,
     and the multi-intent Copilot-CLI 4728-shape MUST still fire.

Output: v5_eval_set.json (same shape as eval_test_set.json so the existing
runner only needs a --data flag, no schema changes).

Each entry: {text, labels (list), category (string)}.
Empty labels list means the example must NOT cross any threshold.
"""
import json
import random
import string
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "v5_eval_set.json"
random.seed(101)

EXAMPLES: list[dict] = []


def add(text: str, labels: list[str], category: str) -> None:
    EXAMPLES.append({"text": text, "labels": labels, "category": category})


# ── FP cases from this conversation (negatives — must be clean) ─────────────
# Mirrors the families in conversation_data.jsonl but uses different surface
# text so it's a true held-out test, not a memorization check.

META_DISCUSSION = [
    # Direct echoes of the actual rows we saw
    "see 4728 prompt fired from copilot cli - same prompt but labels as pii",
    "let me try this with copilot cli",
    "why does this row classify as generic_credential when there is no value",
    "the model triggered auth_token on benign chat",
    "explain why ml flagged row 4719 as service_credential",
    "this is a false positive for key_material on a path-only message",
    "above_threshold list contains pii but the prompt has no email or phone",
    "intent column shows generic_credential 99 percent on conversational text",
    "label this row as benign not auth_token",
    "the rule fired on a meta question about classification",
    "we should add this case as a negative example for v5",
    "why is the classifier confused between description and disclosure",
]
for t in META_DISCUSSION:
    add(t, [], "fp-meta-discussion")

CLI_MENTIONS = [
    "let me try this through the copilot cli",
    "running this with the gh cli now",
    "try the same with claude code",
    "switch to the openai cli for the next test",
    "compare output between the aws cli and gcloud cli",
    "the gh copilot cli isn't picking up the proxy env var",
    "trying with the new cli build that just landed",
    "drop into a repl with the anthropic cli",
    "the kubectl cli supports this flag",
]
for t in CLI_MENTIONS:
    add(t, [], "fp-cli-mention")

SHORT_ACKS = [
    "started",
    "ok let me try",
    "looks good",
    "rerun the build",
    "deploy the staging branch",
    "any updates yet",
    "model is warming up",
    "i restarted the proxy",
    "lowered the threshold",
    "tests pass",
]
for t in SHORT_ACKS:
    add(t, [], "fp-short-ack")

PATH_DESCRIPTIONS = [
    "see my private key located at ~/Downloads/some.pk",
    "the credentials file is at ~/.aws/credentials but i'll redact it",
    "i keep my keys in ~/.ssh as usual",
    "see the bashrc for env exports",
    "secrets live in vault at secret/data/myapp",
    "the cert is at /etc/ssl/certs/myapp.pem",
    "config map is in k8s, key name is API_KEY",
    "tokens are in keychain access not in the repo",
]
for t in PATH_DESCRIPTIONS:
    add(t, [], "fp-path-description")

DEV_CHAT_SECURITY_VOCAB = [
    "rotate keys every 90 days per the policy",
    "validate input at all system boundaries",
    "never log passwords or credentials in plaintext",
    "use environment variables for storing api keys",
    "session tokens are signed jwts",
    "we use a secrets manager for production credentials",
    "rate limit by api key not by ip",
    "the bearer token goes in the authorization header",
    "leaked credentials must be rotated within one hour",
    "documentation about secret management policies",
]
for t in DEV_CHAT_SECURITY_VOCAB:
    add(t, [], "fp-dev-chat-security-vocab")

# Copilot CLI wrapper-text patterns: timestamp + boilerplate around innocuous
# user content. These should NOT fire even though the wrapper is unfamiliar.
COPILOT_CLI_INNOCUOUS_USER = [
    "what files are in this directory",
    "summarize the recent commits",
    "show me the last 10 lines of the log",
    "rebase onto main",
    "format this go file",
    "search for the function handleRequest",
    "list the open pull requests",
    "describe the deployment process",
]
COPILOT_CLI_PREFIXES = [
    "2026-04-27T17:53:16.546Z",
    "2026-05-12T08:11:02.118Z",
    "2025-12-14T22:09:55.001Z",
]
COPILOT_CLI_SUFFIXES = [
    "No tables currently exist. Default tables (todos, todo_deps) will be created automatically when you first use the SQL tool.",
    "MCP server status: connected. Tools available: shell, read_file, sql.",
    "Available tools: shell (run commands), read_file, write_file, sql (read-only).",
]
for txt in COPILOT_CLI_INNOCUOUS_USER:
    pre = random.choice(COPILOT_CLI_PREFIXES)
    suf = random.choice(COPILOT_CLI_SUFFIXES)
    add(f"{pre} {txt} {suf}", [], "fp-copilot-cli-wrapped-innocuous")


# ── TP cases from this conversation (positives — must fire) ─────────────────
# Hostname + user + password (4720 family). Labels: infra + generic_credential.
HOSTS = [
    "xyz.com", "db.internal", "api.staging.corp", "10.0.5.12",
    "prod-redis-01.internal", "vault-shared.eng",
    "auth-server.example.com", "build.ci.internal",
]
USERS = ["u1", "admin", "deploy", "ops", "service", "ci"]
PASSWORDS = ["p1", "hunter2", "changeme", "letmein", "tempPass1", "spring-2025"]

HOST_CRED_TEMPLATES = [
    "my hostname is {h} and username is {u} and password is {p}",
    "server: {h}, user: {u}, pass: {p}",
    "ssh {u}@{h} password {p}",
    "host={h} user={u} password={p}",
    "the box is {h}, login is {u}, password is {p}",
]
for _ in range(15):
    t = random.choice(HOST_CRED_TEMPLATES).format(
        h=random.choice(HOSTS), u=random.choice(USERS), p=random.choice(PASSWORDS),
    )
    add(t, ["infrastructure", "generic_credential"], "tp-hostname-creds")

# DB connection strings — infra + generic_credential (4-label co-fire test).
DB_TEMPLATES = [
    "postgres://{u}:{p}@{h}/app",
    "mysql://{u}:{p}@{h}:3306/orders",
    "DATABASE_URL=postgresql://{u}:{p}@{h}/main",
    "redis://default:{p}@{h}:6379/0",
]
for _ in range(8):
    pwd = random.choice(PASSWORDS) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    t = random.choice(DB_TEMPLATES).format(
        u=random.choice(USERS), p=pwd, h=random.choice(HOSTS),
    )
    add(t, ["infrastructure", "generic_credential"], "tp-db-conn-string")

# Concrete API tokens — service_credential / auth_token.
# Placeholder tokens are used here (not full random-entropy strings) so the
# committed JSON never pattern-matches GitHub's secret-scanning rules. The
# classifier still fires on the surrounding context ("my openai key: …").
TOKEN_CASES = [
    ("<test-openai-token>",    ["service_credential"], "tp-openai-key"),
    ("<test-github-pat>",      ["service_credential"], "tp-github-pat"),
    ("<test-aws-akid>",        ["service_credential"], "tp-aws-access-key"),
    ("Bearer <test-token>",    ["auth_token"],         "tp-bearer-token"),
    ("<test-slack-token>",     ["service_credential"], "tp-slack-bot-token"),
]
for tok, lbl, cat in TOKEN_CASES:
    add(f"my token: {tok}", lbl, cat)

# PEM blocks — key_material with actual high-entropy bytes.
for _ in range(4):
    body = ''.join(random.choices(string.ascii_letters + string.digits + "+/", k=300))
    add(f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----",
        ["key_material"], "tp-pem-private-key")
for _ in range(3):
    body = ''.join(random.choices(string.ascii_letters + string.digits + "+/", k=370))
    add(f"ssh-rsa AAAA{body} user@host", ["key_material"], "tp-ssh-rsa-key")

# Copilot-CLI WRAPPED credential disclosure — same shape as the 4728
# misclassification (was "pii" instead of infra+credential). v5 must still
# fire infra + generic_credential despite the wrapper text contamination.
WRAPPED_CRED_TEMPLATES = [
    "{pre} my hostname is {h} and username is {u} and password is {p} {suf}",
    "{pre} connect to {h} with creds {u} and {p} {suf}",
    "{pre} use {u}:{p} to log into {h} {suf}",
]
for _ in range(8):
    t = random.choice(WRAPPED_CRED_TEMPLATES).format(
        pre=random.choice(COPILOT_CLI_PREFIXES),
        suf=random.choice(COPILOT_CLI_SUFFIXES),
        h=random.choice(HOSTS), u=random.choice(USERS), p=random.choice(PASSWORDS),
    )
    add(t, ["infrastructure", "generic_credential"], "tp-copilot-cli-wrapped-creds")


# ── PII regression — keep coverage of the existing pii positives ────────────
PII_CASES = [
    ("contact me at john.doe@example.com or jane.smith@example.org", ["pii"], "tp-emails"),
    ("call me at 415-555-0123 or 212-555-0144", ["pii"], "tp-phones"),
    ("Patient: Jane Doe, DOB 1985-03-12, MRN 4471902, lives at 123 Main St, Seattle WA 98101",
     ["pii"], "tp-medical-pii"),
]
for text, lbl, cat in PII_CASES:
    add(text, lbl, cat)


# ── Negative regressions: code & docs with credential-adjacent vocab ────────
NEGATIVE_CODE = [
    "func authenticate(token string) error { return validateJWT(token) }",
    "// PasswordHash stores the bcrypt hash, never the plaintext",
    "type Credentials struct { Username string; APIKey string }",
    "if err := db.Authenticate(user, hashed); err != nil { return err }",
    "rotateAPIKey() returns the new key id, not the value",
]
for t in NEGATIVE_CODE:
    add(t, [], "fp-code")

NEGATIVE_DOCS = [
    "Best practice: never commit credentials to source control. Use the secrets manager instead.",
    "Authentication: pass the bearer token in the Authorization header. Tokens expire in 24h.",
    "Do not log passwords or API keys. Validate that secrets are redacted before shipping.",
    "The API key field accepts both bearer tokens and basic auth. Choose one.",
]
for t in NEGATIVE_DOCS:
    add(t, [], "fp-docs")


# ── Write ───────────────────────────────────────────────────────────────────
def main() -> None:
    OUTPUT_PATH.write_text(json.dumps(EXAMPLES, indent=2))
    pos = sum(1 for e in EXAMPLES if e["labels"])
    neg = len(EXAMPLES) - pos
    from collections import Counter
    cats = Counter(e["category"] for e in EXAMPLES)
    print(f"Wrote {len(EXAMPLES)} eval cases to {OUTPUT_PATH}")
    print(f"  positives (must fire):     {pos}")
    print(f"  negatives (must be clean): {neg}\n")
    print("By category:")
    for c, n in sorted(cats.items()):
        print(f"  {c:42s} {n}")


if __name__ == "__main__":
    main()
