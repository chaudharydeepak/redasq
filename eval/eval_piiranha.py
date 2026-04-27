"""
Evaluate a pre-trained DistilBERT PII model against the redasq prompt history.

Uses iiiorg/piiranha-v1-detect-personal-information — a small (~268MB) token
classification model that detects 50+ PII categories. Inference is ~10-50ms
on CPU, so this could realistically run inline in redasq.
"""
import json
import sqlite3
import sys
import textwrap
import time
from pathlib import Path

DB_PATH = Path.home() / ".redasq" / "redasq.db"
MODEL_NAME = "iiiorg/piiranha-v1-detect-personal-information"
SAMPLE_PER_STATUS = 10
MAX_PROMPT_CHARS = 1500


def load_samples(db_path: Path):
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

    print(f"Loading {MODEL_NAME} (first run downloads ~268MB)...", flush=True)
    from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_NAME)
    nlp = pipeline(
        "ner",
        model=model,
        tokenizer=tokenizer,
        aggregation_strategy="simple",
    )
    print("Model loaded.\n", flush=True)

    samples = load_samples(DB_PATH)
    print(f"Evaluating {len(samples)} prompts ({SAMPLE_PER_STATUS} each from clean/redacted/blocked)\n")

    total_latency = 0.0
    for row_id, status, prompt, matches_json in samples:
        text = prompt[:MAX_PROMPT_CHARS]
        existing = fmt_existing_matches(matches_json)

        try:
            start = time.monotonic()
            entities = nlp(text)
            latency = time.monotonic() - start
            total_latency += latency
        except Exception as e:
            print(f"#{row_id} [{status}] ERROR: {e}")
            continue

        if entities:
            ml_summary = "; ".join(
                f"{e['entity_group']}={e['word'][:50]!r}({e['score']:.2f})"
                for e in entities
            )
        else:
            ml_summary = "—"

        print(f"── #{row_id} [{status}] ({latency*1000:.0f}ms) " + "─" * 30)
        print(f"  prompt:   {textwrap.shorten(text, 140)}")
        print(f"  redasq:   {existing}")
        print(f"  ml:       {ml_summary}")
        print()

    if samples:
        avg = total_latency / len(samples) * 1000
        print(f"Average latency: {avg:.0f}ms over {len(samples)} prompts")


if __name__ == "__main__":
    main()
