"""
Run the fine-tuned GLiNER model against EVERY prompt in ~/.redasq/redasq.db.

Writes detailed results to results.jsonl (one line per prompt) and prints
summary stats at the end. Skips very short or very long prompts.
"""
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

DB_PATH = Path.home() / ".redasq" / "redasq.db"
MODEL_DIR = Path(__file__).parent / "gliner_redasq"
RESULTS_PATH = Path(__file__).parent / "results.jsonl"            # all prompts
DISAGREE_PATH = Path(__file__).parent / "disagreements.jsonl"     # only mismatches
LOG_PATH = Path(__file__).parent / "eval_full_db.log"             # console mirror

MIN_PROMPT_CHARS = 30
MAX_PROMPT_CHARS = 50000  # was 5000 — chunking handles long prompts now
THRESHOLD = 0.6

LABELS = [
    "aws_access_key", "github_token", "anthropic_key", "openai_key",
    "stripe_key", "password", "db_connection_string", "email", "ssn",
    "internal_ip", "internal_hostname", "ssh_command", "private_key_file",
    "jwt_token", "credit_card",
]


def load_all(db_path: Path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, status, prompt, matches FROM prompts "
        "WHERE length(prompt) >= ? AND length(prompt) <= ? "
        "ORDER BY id ASC",
        (MIN_PROMPT_CHARS, MAX_PROMPT_CHARS),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def regex_categories(matches_json: str) -> set[str]:
    if not matches_json:
        return set()
    try:
        matches = json.loads(matches_json)
    except json.JSONDecodeError:
        return set()
    if not matches:
        return set()
    return {m.get("rule_id", "?") for m in matches}


def main() -> None:
    if not DB_PATH.exists() or not MODEL_DIR.exists():
        print("DB or model missing", file=sys.stderr)
        sys.exit(1)

    log = LOG_PATH.open("w")

    def out(msg: str = "") -> None:
        print(msg, flush=True)
        log.write(msg + "\n")
        log.flush()

    out(f"Loading model from {MODEL_DIR}...")
    import torch
    from gliner import GLiNER
    device = (
        "cuda" if torch.cuda.is_available()
        else "mps" if hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
        else "cpu"
    )
    model = GLiNER.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model.to(device)
    model.eval()
    out(f"Model loaded on {device}.\n")

    def predict_chunked(text: str, labels_list, threshold: float,
                        max_words: int = 300, overlap: int = 50) -> list[dict]:
        """Sliding-window prediction so long prompts aren't truncated.
        Splits text into overlapping word windows, runs model on each, merges.
        """
        words = text.split()
        if len(words) <= max_words:
            return model.predict_entities(text, labels_list, threshold=threshold)
        seen = set()
        merged = []
        step = max_words - overlap
        for i in range(0, len(words), step):
            window_words = words[i:i + max_words]
            window_text = " ".join(window_words)
            for e in model.predict_entities(window_text, labels_list, threshold=threshold):
                key = (e["text"], e["label"])
                if key in seen:
                    continue
                seen.add(key)
                merged.append(e)
            if i + max_words >= len(words):
                break
        return merged

    rows = load_all(DB_PATH)
    out(f"Processing {len(rows)} prompts (skipping <{MIN_PROMPT_CHARS} or >{MAX_PROMPT_CHARS} chars)\n")

    agreement = Counter()
    ml_label_counts = Counter()
    regex_label_counts = Counter()
    by_status = Counter()
    total_latency = 0.0
    start = time.monotonic()

    with RESULTS_PATH.open("w") as f, DISAGREE_PATH.open("w") as fd:
        for i, (row_id, status, prompt, matches_json) in enumerate(rows):
            text = prompt[:MAX_PROMPT_CHARS]
            regex_set = regex_categories(matches_json)
            for r in regex_set:
                regex_label_counts[r] += 1

            t0 = time.monotonic()
            try:
                entities = predict_chunked(text, LABELS, THRESHOLD)
            except Exception as e:
                entities = []
                out(f"  #{row_id} ERROR: {e}")
            latency = time.monotonic() - t0
            total_latency += latency

            ml_set = {e["label"] for e in entities}
            for l in ml_set:
                ml_label_counts[l] += 1

            if regex_set and ml_set:
                bucket = "both"
            elif regex_set:
                bucket = "only_regex"
            elif ml_set:
                bucket = "only_ml"
            else:
                bucket = "neither"
            agreement[bucket] += 1
            by_status[status] += 1

            row_record = {
                "id": row_id,
                "status": status,
                "bucket": bucket,
                "regex": sorted(regex_set),
                "ml": [
                    {"label": e["label"], "text": e["text"], "score": round(float(e["score"]), 3)}
                    for e in entities
                ],
                "prompt_preview": text[:300],
                "latency_ms": round(latency * 1000),
            }
            f.write(json.dumps(row_record) + "\n")
            # Disagreement file: only mismatches worth reviewing.
            if bucket in ("only_ml", "only_regex"):
                fd.write(json.dumps(row_record) + "\n")

            if (i + 1) % 100 == 0:
                elapsed = time.monotonic() - start
                avg = total_latency / (i + 1) * 1000
                rate = (i + 1) / elapsed
                eta = (len(rows) - i - 1) / max(rate, 0.01)
                out(f"  {i+1}/{len(rows)}  avg={avg:.0f}ms  rate={rate:.1f}/s  ETA={eta:.0f}s")

    elapsed = time.monotonic() - start
    out(f"\nDone in {elapsed:.0f}s ({len(rows)/elapsed:.1f} prompts/s)")
    out(f"Avg latency: {total_latency / max(len(rows),1) * 1000:.0f}ms")
    out(f"\nFiles written:")
    out(f"  {RESULTS_PATH}    (all prompts)")
    out(f"  {DISAGREE_PATH}   (only_ml + only_regex)")
    out(f"  {LOG_PATH}        (this console output)")

    out("\nAgreement matrix:")
    total = sum(agreement.values())
    for k in ("both", "only_regex", "only_ml", "neither"):
        v = agreement[k]
        out(f"  {k:20s} {v:5d}  ({100*v/max(total,1):.1f}%)")

    out("\nBy status:")
    for status, count in by_status.items():
        out(f"  {status:12s} {count}")

    out("\nTop ML labels:")
    for label, count in ml_label_counts.most_common():
        out(f"  {label:25s} {count}")

    out("\nTop regex rule_ids (for reference):")
    for label, count in regex_label_counts.most_common(15):
        out(f"  {label:25s} {count}")

    log.close()


if __name__ == "__main__":
    main()
