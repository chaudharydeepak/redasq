"""
Prepare multi-label intent classification training data for DistilBERT.

Pipeline:
  1. Query ~/.redasq/redasq.db for all prompts.
  2. For each prompt, look at regex matches → map rule_ids to intent labels.
  3. Add hand-curated conversational examples (where regex misses).
  4. Add clean negative examples (no labels).
  5. Output: intent_data.jsonl, one JSON per line: {text, labels: [...]}

Output is multi-label (a single prompt can have multiple intents).
"""
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

DB_PATH = Path.home() / ".redasq" / "redasq.db"
OUTPUT_PATH = Path(__file__).parent / "intent_data.jsonl"

# Cap prompts to avoid extreme outliers; chunking happens at training time.
MIN_CHARS = 30
MAX_CHARS = 8000

# All possible intent labels (multi-label classification).
INTENT_LABELS = [
    "pii",
    "infrastructure",
    "key_material",
    "auth_token",
    "service_credential",
    "generic_credential",
]


def rule_to_intent(rule_id: str) -> str:
    """Map any rule_id to one of the intent labels."""
    rid = rule_id.lower()

    # PII / regulated data
    if rid in ("ssn", "credit-card", "email"):
        return "pii"

    # Network / infrastructure
    if rid in ("internal-ip", "db-connection-string", "ssh-command"):
        return "infrastructure"

    # Key files / certificates / private keys
    if "private-key" in rid or rid.endswith("-key-file") or rid in ("private-key-file",):
        return "key_material"

    # Auth headers / tokens
    if rid in ("http-basic-auth", "http-bearer-token", "jwt-token", "jwt"):
        return "auth_token"

    # Generic catch-all credentials
    if rid in ("generic-api-key", "generic-secret"):
        return "generic_credential"

    # Default: service-specific credential (200+ rules: aws-*, github-*, etc.)
    return "service_credential"


# ── Hand-curated conversational examples regex misses ────────────────────────
CONVERSATIONAL_EXAMPLES = [
    # credential intent (passwords, keys mentioned conversationally)
    ("my password is hunter2", ["generic_credential"]),
    ("the password for the database is Sup3rSecret!", ["generic_credential"]),
    ("rotated to NewProdKey99 this morning", ["generic_credential"]),
    ("use Vault@deploy42 as the new admin pwd", ["generic_credential"]),
    ("the temp password is letmein2026, change after first login", ["generic_credential"]),
    ("I set the redis password to RedisProdKey!", ["generic_credential"]),
    ("user admin password is Pa55w0rd_temp", ["generic_credential"]),
    ("john just shared the prod password its DeployMaster42", ["generic_credential"]),
    ("the failover password we use is FailMe!2024", ["generic_credential"]),
    ("backup pwd: BackupSecret99, store in 1pass", ["generic_credential"]),
    # infrastructure intent (hostnames, IPs in conversation)
    ("the host is rds-prod.internal", ["infrastructure"]),
    ("connect to db1.acme.local for the migration", ["infrastructure"]),
    ("ssh into ec2-user@10.2.3.4 to debug", ["infrastructure"]),
    ("the kafka broker is kafka-3.svc.cluster.local", ["infrastructure"]),
    ("vpc cidr is 10.0.0.0/16", ["infrastructure"]),
    ("internal hostname for the api is api-internal.corp", ["infrastructure"]),
    ("postgres is on rds-staging.internal.aws port 5432", ["infrastructure"]),
    ("vault.internal.company.io is the secrets backend", ["infrastructure"]),
    # key_material intent
    ("ssh -i deploy.pem ec2-user@host", ["key_material", "infrastructure"]),
    ("the private key file is at ~/.ssh/id_ed25519", ["key_material"]),
    ("load /etc/ssl/private/server.key for tls", ["key_material"]),
    ("ca.p12 is the client cert path", ["key_material"]),
    # pii intent
    ("contact user at alice.smith@acme.com about the ticket", ["pii"]),
    ("loop in bob@example.com on the security review", ["pii"]),
    ("the customer's ssn is 123-45-6789", ["pii"]),
    ("charge to card 4242 4242 4242 4242 ending 4242", ["pii"]),
    # multi-intent
    ("ssh to db.prod.internal as admin with password ProdPwd!42",
        ["infrastructure", "generic_credential"]),
    ("use database url postgres://user:Sup3r@10.2.3.4:5432/app",
        ["infrastructure", "generic_credential"]),
    ("my aws key is AKIAIOSFODNN7EXAMPLE for the prod account",
        ["service_credential"]),
    # negatives — no intent (clean conversation)
    ("how do I implement password rotation?", []),
    ("what is the difference between JWT and OAuth?", []),
    ("the database connection is pooled", []),
    ("we should encrypt secrets at rest", []),
    ("PCI compliance requires not storing credit card numbers", []),
    ("ssh keepalive should be 60 seconds", []),
    ("validate email format with a regex", []),
    ("internal IPs are in the 10.x range per rfc1918", []),
    ("password manager integration is in the backlog", []),
    ("the email service is down right now", []),
    ("rotate github tokens every 90 days", []),
    ("PR comment from teammate about the auth flow", []),
    ("debug logs show 401 unauthorized", []),
    ("k8s pod restart due to oom kill", []),
    ("can you review the readme changes?", []),
]


def derive_labels_from_regex(matches_json: str) -> set[str]:
    """Convert a prompt's regex matches into intent labels."""
    if not matches_json:
        return set()
    try:
        matches = json.loads(matches_json)
    except json.JSONDecodeError:
        return set()
    if not matches:
        return set()
    return {rule_to_intent(m.get("rule_id", "")) for m in matches}


def main() -> None:
    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT prompt, matches FROM prompts "
        "WHERE length(prompt) >= ? AND length(prompt) <= ?",
        (MIN_CHARS, MAX_CHARS),
    )
    rows = cur.fetchall()
    conn.close()

    examples: list[dict] = []
    label_counter = Counter()
    multi_label_counter = Counter()

    # 1. From real DB prompts (regex-derived labels).
    for prompt, matches_json in rows:
        labels = sorted(derive_labels_from_regex(matches_json))
        examples.append({"text": prompt, "labels": labels})
        for l in labels:
            label_counter[l] += 1
        multi_label_counter[len(labels)] += 1

    # 2. Hand-curated conversational examples (where regex misses).
    for text, labels in CONVERSATIONAL_EXAMPLES:
        examples.append({"text": text, "labels": sorted(set(labels))})
        for l in labels:
            label_counter[l] += 1
        multi_label_counter[len(set(labels))] += 1

    # Write JSONL.
    with OUTPUT_PATH.open("w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"Wrote {len(examples)} examples → {OUTPUT_PATH}")
    print(f"  from DB: {len(rows)}")
    print(f"  hand-curated: {len(CONVERSATIONAL_EXAMPLES)}\n")

    print("Label frequency (multi-label, so total > examples):")
    for label in INTENT_LABELS:
        n = label_counter[label]
        pct = 100 * n / len(examples)
        print(f"  {label:25s} {n:5d}  ({pct:.1f}%)")

    print("\nLabels per example:")
    for n_labels, count in sorted(multi_label_counter.items()):
        print(f"  {n_labels} labels:  {count:5d}")


if __name__ == "__main__":
    main()
