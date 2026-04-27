"""
Evaluate the fine-tuned GLiNER model on the held-out test set.

Loads test_data.json, runs predictions, computes per-label precision/recall/F1
plus a confusion summary. Designed to run on EC2 (GPU) but works on CPU too.

Run order:
  1. python gen_test_data.py    # creates test_data.json
  2. python eval_test_metrics.py
"""
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import torch

DATA_PATH = Path(__file__).parent / "test_data.json"
MODEL_DIR = Path(__file__).parent / "gliner_redasq"
RESULTS_PATH = Path(__file__).parent / "test_results.jsonl"
LOG_PATH = Path(__file__).parent / "eval_test_metrics.log"

THRESHOLD = 0.6


def main() -> None:
    if not DATA_PATH.exists():
        print(f"Test data not found at {DATA_PATH} — run gen_test_data.py first", file=sys.stderr)
        sys.exit(1)
    if not MODEL_DIR.exists():
        print(f"Model not found at {MODEL_DIR}", file=sys.stderr)
        sys.exit(1)

    log = LOG_PATH.open("w")
    def out(msg: str = "") -> None:
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
    from gliner import GLiNER
    model = GLiNER.from_pretrained(str(MODEL_DIR), local_files_only=True)
    model.to(device)
    model.eval()

    test_data = json.loads(DATA_PATH.read_text())
    out(f"Loaded {len(test_data)} test cases\n")

    # All labels present in the test set.
    labels = sorted({ex["expected_label"] for ex in test_data})
    out(f"Labels under test: {labels}\n")

    # Per-label counters.
    tp = defaultdict(int)   # true positive: model predicted correct label at correct span
    fp = defaultdict(int)   # false positive: model predicted but wrong (or shouldn't have)
    fn = defaultdict(int)   # false negative: model missed a real entity

    adv_tp = 0   # adversarial: correctly predicted nothing
    adv_fp = 0   # adversarial: hallucinated an entity

    total_latency = 0.0
    start = time.monotonic()

    with RESULTS_PATH.open("w") as f:
        for i, ex in enumerate(test_data):
            text = ex["text"]
            t0 = time.monotonic()
            entities = model.predict_entities(text, labels, threshold=THRESHOLD)
            total_latency += time.monotonic() - t0

            expected_value = ex["expected_value"]
            expected_label = ex["expected_label"]
            is_adversarial = ex.get("adversarial", False)

            if is_adversarial:
                if not entities:
                    adv_tp += 1
                else:
                    adv_fp += 1
                    for e in entities:
                        fp[e["label"]] += 1
            else:
                # Positive case — must find expected_value tagged with expected_label.
                hit = False
                for e in entities:
                    if e["label"] == expected_label and (
                        e["text"] == expected_value
                        or e["text"] in expected_value
                        or expected_value in e["text"]
                    ):
                        hit = True
                        break
                if hit:
                    tp[expected_label] += 1
                else:
                    fn[expected_label] += 1
                # Any prediction not matching the expected entity counts as FP.
                for e in entities:
                    if e["label"] != expected_label or (
                        e["text"] != expected_value
                        and e["text"] not in expected_value
                        and expected_value not in e["text"]
                    ):
                        fp[e["label"]] += 1

            f.write(json.dumps({
                "text": text[:200],
                "expected_label": expected_label,
                "expected_value": expected_value,
                "adversarial": is_adversarial,
                "predictions": [
                    {"label": e["label"], "text": e["text"], "score": round(float(e["score"]), 3)}
                    for e in entities
                ],
            }) + "\n")

    elapsed = time.monotonic() - start
    out(f"Processed {len(test_data)} cases in {elapsed:.1f}s "
        f"(avg {total_latency/len(test_data)*1000:.0f}ms/case)\n")

    # ── Per-label metrics ────────────────────────────────────────────────────
    out("Per-label metrics:")
    out(f"  {'label':<25} {'TP':>5} {'FP':>5} {'FN':>5} {'Precision':>10} {'Recall':>8} {'F1':>6}")
    out("  " + "─" * 76)

    macro_p, macro_r, macro_f, n_labels = 0.0, 0.0, 0.0, 0
    total_tp, total_fp, total_fn = 0, 0, 0

    for label in labels:
        t, fp_, fn_ = tp[label], fp[label], fn[label]
        precision = t / (t + fp_) if (t + fp_) > 0 else 0.0
        recall = t / (t + fn_) if (t + fn_) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        out(f"  {label:<25} {t:>5} {fp_:>5} {fn_:>5} {precision:>10.2%} {recall:>8.2%} {f1:>6.2%}")
        if t + fn_ > 0:  # has any positives
            macro_p += precision
            macro_r += recall
            macro_f += f1
            n_labels += 1
        total_tp += t
        total_fp += fp_
        total_fn += fn_

    out("  " + "─" * 76)
    macro_p /= max(n_labels, 1)
    macro_r /= max(n_labels, 1)
    macro_f /= max(n_labels, 1)
    micro_p = total_tp / max(total_tp + total_fp, 1)
    micro_r = total_tp / max(total_tp + total_fn, 1)
    micro_f = 2 * micro_p * micro_r / max(micro_p + micro_r, 1e-9)
    out(f"  {'macro avg':<25} {'':>5} {'':>5} {'':>5} {macro_p:>10.2%} {macro_r:>8.2%} {macro_f:>6.2%}")
    out(f"  {'micro avg':<25} {total_tp:>5} {total_fp:>5} {total_fn:>5} "
        f"{micro_p:>10.2%} {micro_r:>8.2%} {micro_f:>6.2%}")

    out(f"\nAdversarial cases (should NOT be detected):")
    total_adv = adv_tp + adv_fp
    out(f"  correctly ignored: {adv_tp}/{total_adv} ({adv_tp/max(total_adv,1):.1%})")
    out(f"  false positives:   {adv_fp}/{total_adv} ({adv_fp/max(total_adv,1):.1%})")

    out(f"\nFiles:")
    out(f"  {RESULTS_PATH}    (per-case predictions)")
    out(f"  {LOG_PATH}        (this output)")

    log.close()


if __name__ == "__main__":
    main()
