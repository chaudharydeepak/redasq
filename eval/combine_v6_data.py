"""
Combine v4 sources + (regenerated) conversation_data → intent_data_v6.jsonl.

v6 differs from v5 by fixing three labeling/coverage gaps surfaced in the
v5-vs-v4 evaluation:
  1. KEY_FILE_REFS relabeled as key_material POSITIVES (v5 had them wrong)
  2. DB conn-string templates expanded (MONGO_URI, set/export X=, JDBC_URL,
     mongodb+srv:// shapes that v5 didn't generalize to)
  3. New host-only disclosure templates with diverse TLDs (the
     `my db is hosted on jham.jham.com` family)

Run order:
  python gen_conversation_data.py    # regenerate conversation_data.jsonl
  python combine_v6_data.py          # → intent_data_v6.jsonl
  python train_distilbert.py         # defaults to v6 → distilbert_redasq_v6/
  python convert_to_onnx.py          # → distilbert_redasq_v6_onnx/
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent
SOURCES = [
    ROOT / "intent_data_v4.jsonl",         # full v4 training corpus (~43K)
    ROOT / "conversation_data.jsonl",      # v6-regenerated (~4.8K, template-based)
    ROOT / "llm_generated_data.jsonl",     # gen_llm_dataset.py output (~10K, natural-phrasing)
]
OUT = ROOT / "intent_data_v6.jsonl"

random.seed(42)


def load(path: Path) -> list[dict]:
    if not path.exists():
        print(f"  WARNING: {path} missing — skipping")
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    all_ex: list[dict] = []
    for src in SOURCES:
        rows = load(src)
        print(f"  {src.name:40s} {len(rows)}")
        all_ex.extend(rows)
    print()

    seen: dict[str, dict] = {}
    for ex in all_ex:
        seen[ex["text"]] = ex   # later wins on conflict — conversation_data overrides
    deduped = list(seen.values())
    random.shuffle(deduped)

    with OUT.open("w") as f:
        for ex in deduped:
            f.write(json.dumps(ex) + "\n")

    none_count = sum(1 for e in deduped if not e["labels"])
    counter: Counter = Counter()
    for ex in deduped:
        for l in ex["labels"]:
            counter[l] += 1

    print(f"Total raw:       {len(all_ex)}")
    print(f"After dedupe:    {len(deduped)} → {OUT}\n")
    print(f"  no labels (negative):  {none_count}")
    for l, n in counter.most_common():
        print(f"  {l:25s} {n}")


if __name__ == "__main__":
    main()
