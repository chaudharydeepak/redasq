"""
Evaluate the trained DistilBERT model on a held-out hand-crafted test set.

This is the REAL test of generalization — these examples are deliberately
phrased differently from training templates and include adversarial negatives
that look suspicious but aren't. Reports per-category and per-label metrics.

Defaults to v5 model + v5 eval set. Override via CLI flags or env vars:

  python eval_distilbert_test_set.py \
      --data v5_eval_set.json \
      --model distilbert_redasq_v5

  REDASQ_EVAL_DATA=eval_test_set.json \
  REDASQ_EVAL_MODEL=distilbert_redasq_v4 \
  python eval_distilbert_test_set.py
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

ROOT = Path(__file__).parent
DEFAULT_DATA = os.environ.get("REDASQ_EVAL_DATA", "v5_eval_set.json")
DEFAULT_MODEL = os.environ.get("REDASQ_EVAL_MODEL", "distilbert_redasq_v5")

LABELS = [
    "pii", "infrastructure", "key_material", "auth_token",
    "service_credential", "generic_credential",
]
THRESHOLD = 0.5


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=DEFAULT_DATA,
                        help="Eval JSON file (relative to eval/) or absolute path")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Model dir (relative to eval/) or absolute path")
    args = parser.parse_args()

    DATA_PATH = Path(args.data) if Path(args.data).is_absolute() else ROOT / args.data
    MODEL_DIR = Path(args.model) if Path(args.model).is_absolute() else ROOT / args.model
    LOG_PATH = ROOT / (DATA_PATH.stem + ".log")

    if not DATA_PATH.exists():
        print(f"Missing data file: {DATA_PATH}", file=sys.stderr); sys.exit(1)
    if not MODEL_DIR.exists():
        print(f"Missing model dir: {MODEL_DIR}", file=sys.stderr); sys.exit(1)

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

    test_data = json.loads(DATA_PATH.read_text())
    out(f"Loaded {len(test_data)} held-out test cases\n")

    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)

    by_category = defaultdict(lambda: {"correct": 0, "total": 0})
    failures = []

    total_latency = 0.0
    for ex in test_data:
        text = ex["text"]
        expected = set(ex["labels"])
        category = ex.get("category", "uncategorized")

        t0 = time.monotonic()
        enc = tokenizer(text, truncation=True, padding="max_length",
                       max_length=512, return_tensors="pt").to(device)
        with torch.no_grad():
            logits = model(**enc).logits
        probs = torch.sigmoid(logits)[0].cpu().numpy()
        total_latency += time.monotonic() - t0

        predicted = {LABELS[i] for i, p in enumerate(probs) if p >= THRESHOLD}

        for label in LABELS:
            if label in expected and label in predicted:
                tp[label] += 1
            elif label in predicted and label not in expected:
                fp[label] += 1
            elif label in expected and label not in predicted:
                fn[label] += 1

        by_category[category]["total"] += 1
        if predicted == expected:
            by_category[category]["correct"] += 1
        else:
            failures.append({
                "text": text[:200],
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "probs": {l: round(float(probs[i]), 3) for i, l in enumerate(LABELS)},
                "category": category,
            })

    out(f"Avg inference latency: {total_latency/len(test_data)*1000:.1f}ms\n")

    out("Per-label metrics:")
    out(f"  {'label':<25} {'TP':>5} {'FP':>5} {'FN':>5} {'P':>8} {'R':>8} {'F1':>8}")
    out("  " + "-" * 70)
    macro_p = macro_r = macro_f = 0.0
    n = 0
    for label in LABELS:
        t, fp_, fn_ = tp[label], fp[label], fn[label]
        p = t / max(t + fp_, 1)
        r = t / max(t + fn_, 1)
        f1 = 2 * p * r / max(p + r, 1e-9)
        out(f"  {label:<25} {t:>5} {fp_:>5} {fn_:>5} {p:>8.2%} {r:>8.2%} {f1:>8.2%}")
        if t + fn_ > 0:
            macro_p += p
            macro_r += r
            macro_f += f1
            n += 1
    out("  " + "-" * 70)
    out(f"  {'macro avg':<25} {'':>5} {'':>5} {'':>5} {macro_p/max(n,1):>8.2%} {macro_r/max(n,1):>8.2%} {macro_f/max(n,1):>8.2%}")

    out("\nPer-category accuracy (exact label set match):")
    for cat, stats in sorted(by_category.items()):
        acc = stats["correct"] / stats["total"]
        out(f"  {cat:<40} {stats['correct']:>3}/{stats['total']:<3}  {acc:.0%}")

    if failures:
        out(f"\nFailures ({len(failures)} total) — showing first 20:")
        for f in failures[:20]:
            out(f"  ─ category={f['category']}")
            out(f"    text:      {f['text'][:120]}")
            out(f"    expected:  {f['expected']}")
            out(f"    predicted: {f['predicted']}")
            out(f"    probs:     {f['probs']}")

    log.close()


if __name__ == "__main__":
    main()
