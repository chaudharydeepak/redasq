"""
Run the trained DistilBERT intent classifier against ~/.redasq/redasq.db.

Compares predictions against what redasq's regex layer caught. Writes:
  - results.jsonl   (per-prompt predictions)
  - disagreements.jsonl  (only mismatches)
  - eval_distilbert_db.log  (summary stats)
"""
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

DB_PATH = Path.home() / ".redasq" / "redasq.db"
MODEL_DIR = Path(__file__).parent / "distilbert_redasq_v2"   # adjust if testing v1
RESULTS_PATH = Path(__file__).parent / "distilbert_results.jsonl"
DISAGREE_PATH = Path(__file__).parent / "distilbert_disagreements.jsonl"
LOG_PATH = Path(__file__).parent / "eval_distilbert_db.log"

LABELS = [
    "pii", "infrastructure", "key_material", "auth_token",
    "service_credential", "generic_credential",
]
THRESHOLD = 0.5
MIN_CHARS = 30
MAX_CHARS = 50000  # we chunk longer ones
MAX_LENGTH = 512   # tokens per chunk
WINDOW_WORDS = 350
OVERLAP_WORDS = 50


def rule_to_intent(rule_id: str) -> str:
    rid = rule_id.lower()
    if rid in ("ssn", "credit-card", "email"):
        return "pii"
    if rid in ("internal-ip", "db-connection-string", "ssh-command"):
        return "infrastructure"
    if "private-key" in rid or rid.endswith("-key-file"):
        return "key_material"
    if rid in ("http-basic-auth", "http-bearer-token", "jwt-token", "jwt"):
        return "auth_token"
    if rid in ("generic-api-key", "generic-secret"):
        return "generic_credential"
    return "service_credential"


def regex_intents(matches_json: str) -> set[str]:
    if not matches_json:
        return set()
    try:
        matches = json.loads(matches_json)
    except json.JSONDecodeError:
        return set()
    if not matches:
        return set()
    return {rule_to_intent(m.get("rule_id", "")) for m in matches}


def main():
    if not DB_PATH.exists() or not MODEL_DIR.exists():
        print(f"Missing DB ({DB_PATH}) or model ({MODEL_DIR})", file=sys.stderr)
        sys.exit(1)

    log = LOG_PATH.open("w")
    def out(msg=""):
        print(msg, flush=True)
        log.write(msg + "\n")
        log.flush()

    device = (
        "cuda" if torch.cuda.is_available()
        else "mps" if hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
        else "cpu"
    )
    out(f"Device: {device}")
    out(f"Loading model from {MODEL_DIR}...")

    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.to(device)
    model.eval()
    out("Model loaded.\n")

    def predict(text: str) -> dict[str, float]:
        """Predict per-label probabilities. Chunks long prompts and takes max."""
        words = text.split()
        if len(words) <= WINDOW_WORDS:
            chunks = [text]
        else:
            chunks = []
            for i in range(0, len(words), WINDOW_WORDS - OVERLAP_WORDS):
                chunks.append(" ".join(words[i:i + WINDOW_WORDS]))
                if i + WINDOW_WORDS >= len(words):
                    break

        max_probs = np.zeros(len(LABELS))
        for chunk in chunks:
            enc = tokenizer(
                chunk, truncation=True, padding="max_length",
                max_length=MAX_LENGTH, return_tensors="pt",
            ).to(device)
            with torch.no_grad():
                logits = model(**enc).logits
            probs = torch.sigmoid(logits)[0].cpu().numpy()
            max_probs = np.maximum(max_probs, probs)
        return {LABELS[i]: float(max_probs[i]) for i in range(len(LABELS))}

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, status, prompt, matches FROM prompts "
        "WHERE length(prompt) >= ? AND length(prompt) <= ? "
        "ORDER BY id ASC",
        (MIN_CHARS, MAX_CHARS),
    )
    rows = cur.fetchall()
    conn.close()
    out(f"Processing {len(rows)} prompts\n")

    agreement = Counter()
    by_status = Counter()
    pred_label_counts = Counter()
    regex_label_counts = Counter()
    total_latency = 0.0
    start = time.monotonic()

    with RESULTS_PATH.open("w") as f, DISAGREE_PATH.open("w") as fd:
        for i, (row_id, status, prompt, matches_json) in enumerate(rows):
            text = prompt[:MAX_CHARS]
            regex_set = regex_intents(matches_json)
            for r in regex_set:
                regex_label_counts[r] += 1

            t0 = time.monotonic()
            try:
                probs = predict(text)
            except Exception as e:
                probs = {l: 0.0 for l in LABELS}
                out(f"  #{row_id} ERROR: {e}")
            total_latency += time.monotonic() - t0

            pred_set = {l for l, p in probs.items() if p >= THRESHOLD}
            for l in pred_set:
                pred_label_counts[l] += 1

            if regex_set and pred_set:
                bucket = "both"
            elif regex_set:
                bucket = "only_regex"
            elif pred_set:
                bucket = "only_ml"
            else:
                bucket = "neither"
            agreement[bucket] += 1
            by_status[status] += 1

            row_record = {
                "id": row_id,
                "status": status,
                "bucket": bucket,
                "regex_intents": sorted(regex_set),
                "ml_intents": sorted(pred_set),
                "ml_probs": {l: round(p, 3) for l, p in probs.items()},
                "prompt_preview": text[:300],
            }
            f.write(json.dumps(row_record) + "\n")
            if bucket in ("only_ml", "only_regex") or (
                bucket == "both" and regex_set != pred_set
            ):
                fd.write(json.dumps(row_record) + "\n")

            if (i + 1) % 200 == 0:
                elapsed = time.monotonic() - start
                rate = (i + 1) / elapsed
                eta = (len(rows) - i - 1) / max(rate, 0.01)
                avg_ms = total_latency / (i + 1) * 1000
                out(f"  {i+1}/{len(rows)}  avg={avg_ms:.0f}ms  rate={rate:.1f}/s  ETA={eta:.0f}s")

    elapsed = time.monotonic() - start
    out(f"\nDone in {elapsed:.0f}s ({len(rows)/elapsed:.1f} prompts/s)")
    out(f"Avg latency: {total_latency/max(len(rows),1)*1000:.0f}ms")

    out("\nAgreement matrix (intent-level):")
    total = sum(agreement.values())
    for k in ("both", "only_regex", "only_ml", "neither"):
        v = agreement[k]
        out(f"  {k:20s} {v:5d}  ({100*v/max(total,1):.1f}%)")

    out("\nML intent counts:")
    for label, n in pred_label_counts.most_common():
        out(f"  {label:25s} {n}")
    out("\nRegex intent counts (for comparison):")
    for label, n in regex_label_counts.most_common():
        out(f"  {label:25s} {n}")

    log.close()


if __name__ == "__main__":
    main()
