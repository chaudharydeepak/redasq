"""
Evaluate the fine-tuned GLiNER model on real prompts from ~/.redasq/redasq.db.

Compares ML predictions against what redasq's regex layer caught for the same
prompts. Output groups results by status (clean/redacted/blocked) and prints:
  - regex matches  (what your current rules caught)
  - ml predictions (what the fine-tuned model thinks)
"""
import json
import sqlite3
import sys
import textwrap
import time
from pathlib import Path

DB_PATH = Path.home() / ".redasq" / "redasq.db"
MODEL_DIR = Path(__file__).parent / "gliner_redasq"
SAMPLE_PER_STATUS = 15
MAX_PROMPT_CHARS = 1500
THRESHOLD = 0.6  # min confidence for ML hits

# Labels the fine-tuned model knows (must match training data labels).
LABELS = [
    "aws_access_key", "github_token", "anthropic_key", "openai_key",
    "stripe_key", "password", "db_connection_string", "email", "ssn",
    "internal_ip", "internal_hostname", "ssh_command", "private_key_file",
    "jwt_token", "credit_card",
]


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
    if not MODEL_DIR.exists():
        print(f"Model not found: {MODEL_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading fine-tuned model from {MODEL_DIR}...")
    from gliner import GLiNER
    model = GLiNER.from_pretrained(str(MODEL_DIR), local_files_only=True)
    print("Model loaded.\n")

    samples = load_samples(DB_PATH)
    print(f"Evaluating {len(samples)} prompts ({SAMPLE_PER_STATUS} each from clean/redacted/blocked)\n")

    total_latency = 0.0
    agreement = {"both": 0, "only_regex": 0, "only_ml": 0, "neither": 0}

    for row_id, status, prompt, matches_json in samples:
        text = prompt[:MAX_PROMPT_CHARS]
        existing = fmt_existing_matches(matches_json)

        try:
            t0 = time.monotonic()
            entities = model.predict_entities(text, LABELS, threshold=THRESHOLD)
            latency = time.monotonic() - t0
            total_latency += latency
        except Exception as e:
            print(f"#{row_id} [{status}] ERROR: {e}")
            continue

        if entities:
            ml_summary = "; ".join(
                f"{e['label']}={e['text'][:40]!r}({e['score']:.2f})"
                for e in entities
            )
        else:
            ml_summary = "—"

        regex_hit = existing != "—"
        ml_hit = bool(entities)
        if regex_hit and ml_hit:
            agreement["both"] += 1
        elif regex_hit:
            agreement["only_regex"] += 1
        elif ml_hit:
            agreement["only_ml"] += 1
        else:
            agreement["neither"] += 1

        print(f"── #{row_id} [{status}] ({latency*1000:.0f}ms) " + "─" * 30)
        print(f"  prompt:   {textwrap.shorten(text, 140)}")
        print(f"  regex:    {existing}")
        print(f"  ml:       {ml_summary}")
        print()

    if samples:
        avg = total_latency / len(samples) * 1000
        print(f"\nAverage ML latency: {avg:.0f}ms over {len(samples)} prompts")
        print(f"Agreement matrix:")
        print(f"  both regex+ML caught:  {agreement['both']}")
        print(f"  only regex caught:     {agreement['only_regex']}")
        print(f"  only ML caught:        {agreement['only_ml']}")
        print(f"  neither caught:        {agreement['neither']}")


if __name__ == "__main__":
    main()
