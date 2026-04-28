"""
Run the held-out 490-prompt eval set directly against v6 ONNX (no sidecar,
no HTTP, no proxy interaction). Produces an aggregated summary only — does
not echo prompt text into stdout, so the output is safe to surface through
redasq without tripping rules.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

ROOT = Path(__file__).parent
MODEL_DIR = ROOT / "distilbert_redasq_v6_onnx"
DATA_PATH = ROOT / "local_eval_500.jsonl"


def main() -> None:
    if not MODEL_DIR.exists():
        print(f"missing model: {MODEL_DIR}", file=sys.stderr); sys.exit(1)
    if not DATA_PATH.exists():
        print(f"missing data: {DATA_PATH}", file=sys.stderr); sys.exit(1)

    cfg = json.loads((MODEL_DIR / "redasq_config.json").read_text())
    labels: list[str] = cfg["labels"]
    thresholds: dict[str, float] = cfg["thresholds"]
    max_len: int = cfg.get("max_length", 512)

    print(f"Model: {MODEL_DIR.name}")
    print(f"Labels: {labels}")
    print(f"Thresholds: {thresholds}\n")

    session = ort.InferenceSession(str(MODEL_DIR / "model.onnx"), providers=["CPUExecutionProvider"])
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))

    examples = [json.loads(line) for line in DATA_PATH.read_text().splitlines() if line.strip()]
    print(f"Loaded {len(examples)} examples\n")

    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)

    exact_match = 0
    pos_exact = 0; pos_total = 0
    neg_exact = 0; neg_total = 0
    multi_exact = 0; multi_total = 0

    failures_by_kind: Counter = Counter()
    label_misses: Counter = Counter()
    label_spurious: Counter = Counter()

    latencies: list[float] = []

    for ex in examples:
        text = ex["text"]
        expected = set(ex["labels"])
        is_neg = len(expected) == 0
        is_multi = len(expected) > 1
        if is_neg: neg_total += 1
        else: pos_total += 1
        if is_multi: multi_total += 1

        import time
        t0 = time.monotonic()
        enc = tokenizer(text, truncation=True, padding="max_length", max_length=max_len, return_tensors="np")
        feeds = {
            "input_ids": enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
        }
        logits = session.run(["logits"], feeds)[0]
        probs = 1.0 / (1.0 + np.exp(-logits))[0]
        latencies.append(time.monotonic() - t0)

        predicted = {labels[i] for i, p in enumerate(probs) if p >= thresholds.get(labels[i], 0.5)}

        for label in labels:
            if label in expected and label in predicted: tp[label] += 1
            elif label in predicted and label not in expected:
                fp[label] += 1
                label_spurious[label] += 1
            elif label in expected and label not in predicted:
                fn[label] += 1
                label_misses[label] += 1

        if predicted == expected:
            exact_match += 1
            if is_neg: neg_exact += 1
            else: pos_exact += 1
            if is_multi: multi_exact += 1
        else:
            if is_neg:
                # FP — predicted something on a benign prompt
                failures_by_kind["false_positive_on_benign"] += 1
            elif is_multi and predicted.issubset(expected):
                # Partial — got some labels but missed at least one
                failures_by_kind["partial_multi_label_miss"] += 1
            elif is_multi and predicted - expected:
                failures_by_kind["multi_label_extra_predicted"] += 1
            elif not predicted and not is_neg:
                # Missed entirely
                failures_by_kind["false_negative_complete_miss"] += 1
            elif predicted != expected:
                # Wrong label fired
                failures_by_kind["wrong_label"] += 1

    # ── Print summary ────────────────────────────────────────────────────────
    print(f"Avg inference latency: {np.mean(latencies)*1000:.1f}ms")
    print(f"Median:                {np.median(latencies)*1000:.1f}ms")
    print(f"P95:                   {np.percentile(latencies, 95)*1000:.1f}ms\n")

    print("Per-label metrics:")
    print(f"  {'label':<22} {'TP':>4} {'FP':>4} {'FN':>4} {'P':>8} {'R':>8} {'F1':>8}")
    print("  " + "-" * 64)
    macro_p = macro_r = macro_f = 0.0
    n_with_pos = 0
    for label in labels:
        t, fp_, fn_ = tp[label], fp[label], fn[label]
        p = t / max(t + fp_, 1)
        r = t / max(t + fn_, 1)
        f1 = 2 * p * r / max(p + r, 1e-9)
        print(f"  {label:<22} {t:>4} {fp_:>4} {fn_:>4} {p:>8.2%} {r:>8.2%} {f1:>8.2%}")
        if t + fn_ > 0:
            macro_p += p; macro_r += r; macro_f += f1; n_with_pos += 1
    print("  " + "-" * 64)
    print(f"  {'macro avg':<22} {'':>4} {'':>4} {'':>4} {macro_p/max(n_with_pos,1):>8.2%} {macro_r/max(n_with_pos,1):>8.2%} {macro_f/max(n_with_pos,1):>8.2%}\n")

    print("Bucket accuracy (exact label-set match):")
    print(f"  positives:    {pos_exact}/{pos_total}    {pos_exact/max(pos_total,1):.1%}")
    print(f"  negatives:    {neg_exact}/{neg_total}    {neg_exact/max(neg_total,1):.1%}")
    print(f"  multi-label:  {multi_exact}/{multi_total}    {multi_exact/max(multi_total,1):.1%}")
    print(f"  overall:      {exact_match}/{len(examples)}    {exact_match/len(examples):.1%}\n")

    if failures_by_kind:
        print("Failure breakdown:")
        for kind, n in failures_by_kind.most_common():
            print(f"  {kind:<32} {n}")
        print()

    if label_misses:
        print("Most-missed labels (false negatives):")
        for label, n in label_misses.most_common():
            print(f"  {label:<22} {n}")
        print()
    if label_spurious:
        print("Most-spurious labels (false positives):")
        for label, n in label_spurious.most_common():
            print(f"  {label:<22} {n}")


if __name__ == "__main__":
    main()
