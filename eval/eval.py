"""
Evaluate GLiNER against the redasq prompt history.

Reads sample prompts from ~/.redasq/redasq.db, runs GLiNER over each,
and prints what GLiNER detects vs what redasq's regex rules already caught.
"""
import json
import os
import sqlite3
import sys
import textwrap
from pathlib import Path

DB_PATH = Path.home() / ".redasq" / "redasq.db"
SAMPLE_PER_STATUS = 10
MAX_PROMPT_CHARS = 1500  # GLiNER context window — truncate long prompts
CONFIDENCE_THRESHOLD = 0.55

# Labels we want GLiNER to detect. Curated for credentials + infrastructure
# leakage relevant to LLM prompts.
LABELS = [
    "password",
    "api key",
    "secret token",
    "private ssh key",
    "username",
    "internal hostname",
    "internal ip address",
    "database connection string",
    "email address",
    "phone number",
    "credit card number",
    "social security number",
    "AWS access key id",
    "github personal access token",
]


def load_samples(db_path: Path):
    """Pull a balanced sample of prompts from the redasq DB."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    samples = []
    for status in ("clean", "redacted", "blocked"):
        cur.execute(
            "SELECT id, status, prompt, matches FROM prompts "
            "WHERE status = ? AND length(prompt) > 50 AND length(prompt) < 5000 "
            "ORDER BY id DESC LIMIT ?",
            (status, SAMPLE_PER_STATUS),
        )
        samples.extend(cur.fetchall())
    conn.close()
    return samples


def fmt_existing_matches(matches_json: str) -> str:
    if not matches_json:
        return "—"
    try:
        matches = json.loads(matches_json)
    except json.JSONDecodeError:
        return "?"
    if not matches:
        return "—"
    return ", ".join(m.get("rule_name", "?") for m in matches)


def main() -> None:
    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    print("Loading GLiNER model (first run downloads ~200MB)...", flush=True)
    from gliner import GLiNER  # imported here so the script can be inspected without the dep

    model = GLiNER.from_pretrained("urchade/gliner_multi-v2.1")
    print("Model loaded.\n", flush=True)

    samples = load_samples(DB_PATH)
    print(f"Evaluating {len(samples)} prompts ({SAMPLE_PER_STATUS} each from clean/redacted/blocked)\n")

    for row_id, status, prompt, matches_json in samples:
        text = prompt[:MAX_PROMPT_CHARS]
        existing = fmt_existing_matches(matches_json)

        try:
            entities = model.predict_entities(text, LABELS, threshold=CONFIDENCE_THRESHOLD)
        except Exception as e:
            print(f"#{row_id} [{status}] ERROR: {e}")
            continue

        gliner_summary = (
            ", ".join(f"{e['label']}={e['text'][:40]!r}({e['score']:.2f})" for e in entities)
            if entities else "—"
        )

        print(f"── #{row_id} [{status}] " + "─" * 40)
        print(f"  prompt:   {textwrap.shorten(text, 140)}")
        print(f"  redasq:   {existing}")
        print(f"  gliner:   {gliner_summary}")
        print()


if __name__ == "__main__":
    main()
