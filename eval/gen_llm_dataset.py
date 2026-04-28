"""
LLM-generated training dataset for the redasq DistilBERT classifier.

This is a deliberate departure from the template-based generators — those hit
a phrasing-space ceiling (the model learns surface forms, not semantic
intent). Instead we ask Claude to produce natural prompts an actual engineer
would type, with full freedom over verb choice, sentence structure, formality,
and context. Each intent gets ~1500 positives; ~2800 negatives cover the FP
shapes that frustrated us in production (meta-discussion of the system,
CLI-tool mentions, security-vocabulary dev chat, etc.).

Run with:
  ANTHROPIC_API_KEY=sk-ant-... python gen_llm_dataset.py

Costs ~ $0.50 on Claude Haiku 4.5 for 10K examples (~500K output tokens).
Output: llm_generated_data.jsonl (~10K lines), ready for combine_v6_data.py.

Notes
- We use Haiku for cost. Sonnet would be more diverse but ~30× more expensive
  for marginal gain on this task.
- Each call asks for 50 examples to keep prompts small + outputs scoped.
- We dedupe by exact text at the end. Expect ~10–15% dedup rate; the script
  oversamples by 15% to compensate.
- Multi-label cases (e.g. "host + creds" should fire infrastructure +
  generic_credential) are generated separately so labels stay accurate.
"""
import json
import os
import random
import re
import sys
import time
from pathlib import Path

try:
    from anthropic import Anthropic
except ImportError:
    print("Install: pip install anthropic", file=sys.stderr)
    sys.exit(1)

OUT_PATH = Path(os.environ.get("REDASQ_OUT", str(Path(__file__).parent / "llm_generated_data.jsonl")))
MODEL = os.environ.get("REDASQ_LLM_MODEL", "claude-haiku-4-5-20251001")
BATCH_SIZE = 50
# Defaults size for held-out evaluation set (~2K). Override via env vars.
PER_INTENT_TARGET = int(os.environ.get("REDASQ_PER_INTENT", "300"))   # 6 × 300 = 1800 positives
MULTI_LABEL_TARGET = int(os.environ.get("REDASQ_MULTI", "100"))       # 100 multi-label cases
NEGATIVE_TARGET = int(os.environ.get("REDASQ_NEG", "500"))            # 500 negatives
OVERSAMPLE = 1.15            # +15% to absorb dedup losses
# Set REDASQ_STYLE=internet for evaluation-style prompts that mirror public
# patterns (gitleaks, CVEs, Stack Overflow, advisories) instead of the
# canonical training-style prompts. Used when generating held-out eval data.
STYLE = os.environ.get("REDASQ_STYLE", "training")

# ── Intent taxonomy + canonical seeds ────────────────────────────────────────
# Seeds are NOT template patterns — they're examples of what the intent looks
# like when an engineer leaks something. The model is asked to RIFF on them
# (different verbs, different structure, different files/tokens), not copy.

INTENTS = {
    "pii": {
        "definition": "personal identifying information about a real person — "
                      "email addresses, phone numbers, full names with identifiers, "
                      "addresses, SSN/medical/government IDs, dates of birth, etc. "
                      "Does NOT include service account names or generic 'admin'/'root'.",
        "seeds": [
            "loop in raj.patel@bigco.com about the rotation",
            "Patient Jane Doe DOB 1985-03-12 lives at 123 Main St",
            "call our primary contact at 415-555-0188",
            "the customer's SSN is on the medical chart",
        ],
    },
    "infrastructure": {
        "definition": "internal hostnames, IP addresses, service URLs, cluster "
                      "addresses, container names, internal endpoints, "
                      "database server names. Anything that names a SPECIFIC "
                      "internal/private system.",
        "seeds": [
            "ssh into the bastion at 10.244.5.12",
            "my db is hosted on jham.jham.com",
            "the kafka cluster is at kafka-prod-01.svc.cluster.local",
            "we deploy through prod-gateway.internal",
        ],
    },
    "key_material": {
        "definition": "actual cryptographic keys (PEM blocks, ssh-rsa AAAA…), "
                      "OR explicit references to private key / cert files / "
                      "credential files by path or name (`my key is at ~/x.pem`, "
                      "`read /etc/secrets/master.key`, `the .pfx file in Downloads`).",
        "seeds": [
            "read my private key at ~/Downloads/pvt.key",
            "see the cert file /etc/ssl/certs/myapp.pem",
            "ssh -i ~/Downloads/keypair.pem ec2-user@host",
            "decrypt with the gpg secring at ~/.gnupg/secring.gpg",
        ],
    },
    "auth_token": {
        "definition": "session tokens, JWTs, bearer tokens, OAuth access tokens. "
                      "Tokens that authenticate a request rather than identify "
                      "a long-lived service credential.",
        "seeds": [
            "Authorization: Bearer <test-token>",
            "Cookie: session=<test-jwt>",
            "the OAuth access token expired",
            "use this id_token: <test-jwt>",
        ],
    },
    "service_credential": {
        "definition": "long-lived service account credentials with recognizable "
                      "prefixes — OpenAI sk-, GitHub ghp_, AWS AKIA, Slack xoxb-, "
                      "Stripe sk_live_, Google ya29., GitLab glpat-, etc. "
                      "ALSO: 'my <vendor> key is …' even without the literal blob.",
        "seeds": [
            "my openai key: <test-openai-token>",
            "github pat: <test-github-pat>",
            "aws access key id: <test-aws-akid>",
            "the slack bot token <test-slack-token>",
        ],
    },
    "generic_credential": {
        "definition": "passwords, generic API keys, basic-auth pairs, OAuth "
                      "client_id/client_secret pairs, database passwords. "
                      "Catches credentials that don't have a service-specific prefix.",
        "seeds": [
            "username u1 password p1",
            "my client id is u1 and secret is p1",
            "DATABASE_URL=postgres://user:<test-pwd>@host/db",
            "the build key is hunter2",
        ],
    },
}

# Multi-label disclosures (most common combinations)
MULTI_LABEL_BUCKETS = [
    {
        "labels": ["infrastructure", "generic_credential"],
        "definition": "a disclosure that names BOTH an internal host AND a credential to access it",
        "seeds": [
            "my hostname is jham.jham.com and password is hunter2",
            "ssh deploy@10.0.5.12 password changeme",
            "DATABASE_URL=postgres://app:<test-pwd>@rds-prod.eu.amazonaws.internal/main",
        ],
    },
    {
        "labels": ["pii", "service_credential"],
        "definition": "an email address combined with a leaked vendor token in the same message",
        "seeds": [
            "send raj.patel@bigco.com the new aws key <test-aws-akid>",
            "loop alice@example.com about rotating <test-github-pat>",
        ],
    },
]

# Negatives — what the model must NOT fire on. Categories drawn from real
# false positives we hit on v5.
NEGATIVE_BUCKETS = [
    {
        "category": "meta_discussion",
        "definition": "an engineer talking ABOUT the classification system, "
                      "labels, rules, ML predictions — not actually disclosing anything.",
        "seeds": [
            "why does this row classify as generic_credential",
            "the rule fired but no real value present",
            "this is a false positive for key_material",
            "above_threshold list contains pii but the prompt is benign",
        ],
    },
    {
        "category": "cli_tool_mention",
        "definition": "casual mentions of CLI tools (gh, aws, kubectl, copilot, "
                      "claude code) without any credential value.",
        "seeds": [
            "let me try this with copilot cli",
            "running with the aws cli now",
            "switch to the kubectl context",
        ],
    },
    {
        "category": "dev_chat_security_vocab",
        "definition": "engineers discussing security/credentials policy in the "
                      "abstract — no actual values pasted.",
        "seeds": [
            "rotate keys every 90 days per policy",
            "validate input at all system boundaries",
            "secrets manager handles production credentials",
            "the bearer token goes in the authorization header",
        ],
    },
    {
        "category": "code_snippets",
        "definition": "code that names credential-related identifiers but "
                      "doesn't paste real values (struct fields, function names).",
        "seeds": [
            "func authenticate(token string) error { return validateJWT(token) }",
            "type Credentials struct { Username string; APIKey string }",
            "// PasswordHash stores bcrypt, never plaintext",
        ],
    },
    {
        "category": "build_log_or_command",
        "definition": "build output, git output, deploy logs — looks technical "
                      "but contains no actual secrets.",
        "seeds": [
            "tests pass",
            "merging now",
            "rebased on main",
            "deploy to staging completed in 2m 14s",
        ],
    },
    {
        "category": "documentation",
        "definition": "documentation about credential handling that mentions "
                      "tokens/keys/passwords in the abstract.",
        "seeds": [
            "the API key field accepts both bearer tokens and basic auth",
            "session tokens expire after 24h — re-auth via refresh token",
            "never commit credentials to source control",
        ],
    },
]


GEN_PROMPT_POSITIVE = """\
You are generating training data for a security ML classifier. We need natural
prompts that an engineer would actually type that DISCLOSE the following:

INTENT: {intent}
DEFINITION: {definition}

Here are 4 seed examples (DO NOT copy these — riff on the intent in
distinctly different ways):
{seeds}

Generate exactly {n} new prompts. Vary HARD across:
- verb choice (read/see/check/look at/grab/load/fetch/dump/cat/parse/decrypt/extract)
- sentence framing (declarative / imperative / question / exasperated / matter-of-fact)
- length (some 5 words, some 30+ words)
- formality (casual chat / Slack / commit message / code comment / formal email)
- context wrapper (mid-sentence, leading, trailing, with punctuation noise)
- file path style (absolute, ~/, relative, with/without quotes)
- presence of unrelated context (sometimes the disclosure is buried inside chat)

CRITICAL: Each prompt must actually contain something that fits the intent
definition. Do NOT generate prompts that just talk ABOUT the intent — they
must contain something a security tool should flag.

When you need a token/password/identifier blob, USE THESE PLACEHOLDERS:
  <test-openai-token>, <test-github-pat>, <test-aws-akid>, <test-slack-token>,
  <test-stripe-key>, <test-jwt>, <test-pwd>, <test-token>

Output: one prompt per line. NO numbering. NO quotes. NO commentary. Just the
prompts, separated by newlines.
"""

GEN_PROMPT_NEGATIVE = """\
You are generating BENIGN training prompts for a security ML classifier — text
that looks security-adjacent but does NOT actually disclose anything sensitive.

CATEGORY: {category}
DEFINITION: {definition}

Here are 4 seed examples (riff on the spirit, don't copy):
{seeds}

Generate exactly {n} new prompts. Vary HARD across phrasing, length,
formality, sentence structure. Each one must be something a security ML
classifier should NOT flag — they sound credential-adjacent or use
security vocabulary but contain NO actual secret values.

Output: one prompt per line. NO numbering. NO quotes. NO commentary.
"""


def call_llm(client: Anthropic, prompt: str, max_tokens: int = 4000) -> list[str]:
    resp = client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.content[0].text
    lines = [ln.strip() for ln in text.split("\n")]
    # Drop empty lines, accidental quoting, accidental numbering, accidental commentary lines.
    cleaned = []
    for ln in lines:
        if not ln:
            continue
        # Strip surrounding quotes
        if (ln.startswith('"') and ln.endswith('"')) or (ln.startswith("'") and ln.endswith("'")):
            ln = ln[1:-1].strip()
        # Strip leading numbering ("12. ", "12) ", "- ", "* ")
        ln = re.sub(r"^\s*(?:\d+[.)]\s+|[-*]\s+)", "", ln)
        # Skip lines that are obviously model commentary
        if len(ln) < 4 or len(ln) > 600:
            continue
        if ln.lower().startswith(("here are", "below are", "i'll generate", "sure,", "okay,", "got it")):
            continue
        cleaned.append(ln)
    return cleaned


def generate_intent(client: Anthropic, intent: str, info: dict, target: int) -> list[dict]:
    """Generate `target` examples for a single-label intent."""
    needed = int(target * OVERSAMPLE)
    seen: set[str] = set()
    out: list[dict] = []
    while len(out) < needed:
        prompt = GEN_PROMPT_POSITIVE.format(
            intent=intent,
            definition=info["definition"],
            seeds="\n".join(f"  - {s}" for s in info["seeds"]),
            n=BATCH_SIZE,
        )
        try:
            batch = call_llm(client, prompt)
        except Exception as e:
            print(f"  ! {intent}: API error {e}; retrying in 5s", file=sys.stderr)
            time.sleep(5)
            continue
        for line in batch:
            if line in seen:
                continue
            seen.add(line)
            out.append({"text": line, "labels": [intent]})
        print(f"  {intent}: {len(out)}/{needed}", file=sys.stderr)
    return out[:target]


def generate_multi_label(client: Anthropic, bucket: dict, target: int) -> list[dict]:
    """Generate examples that should fire MULTIPLE labels."""
    label_str = " + ".join(bucket["labels"])
    needed = int(target * OVERSAMPLE)
    seen: set[str] = set()
    out: list[dict] = []
    while len(out) < needed:
        prompt = GEN_PROMPT_POSITIVE.format(
            intent=label_str,
            definition=bucket["definition"],
            seeds="\n".join(f"  - {s}" for s in bucket["seeds"]),
            n=BATCH_SIZE,
        )
        try:
            batch = call_llm(client, prompt)
        except Exception as e:
            print(f"  ! multi:{label_str}: {e}; retrying", file=sys.stderr)
            time.sleep(5)
            continue
        for line in batch:
            if line in seen:
                continue
            seen.add(line)
            out.append({"text": line, "labels": list(bucket["labels"])})
        print(f"  multi:{label_str}: {len(out)}/{needed}", file=sys.stderr)
    return out[:target]


def generate_negatives(client: Anthropic, bucket: dict, target: int) -> list[dict]:
    needed = int(target * OVERSAMPLE)
    seen: set[str] = set()
    out: list[dict] = []
    while len(out) < needed:
        prompt = GEN_PROMPT_NEGATIVE.format(
            category=bucket["category"],
            definition=bucket["definition"],
            seeds="\n".join(f"  - {s}" for s in bucket["seeds"]),
            n=BATCH_SIZE,
        )
        try:
            batch = call_llm(client, prompt)
        except Exception as e:
            print(f"  ! neg:{bucket['category']}: {e}; retrying", file=sys.stderr)
            time.sleep(5)
            continue
        for line in batch:
            if line in seen:
                continue
            seen.add(line)
            out.append({"text": line, "labels": []})
        print(f"  neg:{bucket['category']}: {len(out)}/{needed}", file=sys.stderr)
    return out[:target]


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY", file=sys.stderr)
        sys.exit(1)
    client = Anthropic()

    examples: list[dict] = []

    print(f"Model: {MODEL}", file=sys.stderr)
    print(f"\n=== Single-intent positives (~{PER_INTENT_TARGET} each) ===", file=sys.stderr)
    for intent, info in INTENTS.items():
        examples.extend(generate_intent(client, intent, info, PER_INTENT_TARGET))

    print(f"\n=== Multi-label positives (~{MULTI_LABEL_TARGET // len(MULTI_LABEL_BUCKETS)} each) ===", file=sys.stderr)
    per_bucket = MULTI_LABEL_TARGET // len(MULTI_LABEL_BUCKETS)
    for bucket in MULTI_LABEL_BUCKETS:
        examples.extend(generate_multi_label(client, bucket, per_bucket))

    print(f"\n=== Negatives (~{NEGATIVE_TARGET // len(NEGATIVE_BUCKETS)} each) ===", file=sys.stderr)
    per_neg = NEGATIVE_TARGET // len(NEGATIVE_BUCKETS)
    for bucket in NEGATIVE_BUCKETS:
        examples.extend(generate_negatives(client, bucket, per_neg))

    # Final dedupe across the whole set
    seen: dict[str, dict] = {}
    for ex in examples:
        seen[ex["text"]] = ex
    deduped = list(seen.values())
    random.shuffle(deduped)

    with OUT_PATH.open("w") as f:
        for ex in deduped:
            f.write(json.dumps(ex) + "\n")

    from collections import Counter
    label_counts: Counter = Counter()
    none_count = 0
    for ex in deduped:
        if not ex["labels"]:
            none_count += 1
        for l in ex["labels"]:
            label_counts[l] += 1

    print(f"\n=== Done ===", file=sys.stderr)
    print(f"Total: {len(deduped)} (after dedupe)", file=sys.stderr)
    print(f"  negatives: {none_count}", file=sys.stderr)
    for l, n in label_counts.most_common():
        print(f"  {l:25s} {n}", file=sys.stderr)
    print(f"\nWrote {OUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
