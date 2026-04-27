"""
Combine v4 sources + conversation_data → intent_data_v5.jsonl for v5 training.

v5 differs from v4 by adding ~4000 examples derived from real false-positives /
true-positives observed while debugging the proxy in production conversations.
The new examples target FP categories the v4 model is over-firing on
(meta-discussion of classification, CLI tool mentions, dev chat using
security-domain vocabulary) and reinforce true-positive patterns the model
gets right but only narrowly.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent
# intent_data_v4.jsonl is the actual corpus that was fed to v4 training
# (v2 + targeted_negatives merged via combine_v4_data.py — ~36K examples).
# It lives on the EC2 box; locally we only have its smaller pieces.
SOURCES = [
    ROOT / "intent_data_v4.jsonl",         # full v4 training corpus
    ROOT / "conversation_data.jsonl",      # new: this conversation
]
OUT = ROOT / "intent_data_v5.jsonl"

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

    # De-dupe by exact text — late additions win on label conflict (we want
    # the conversation_data labels to override stale earlier labels).
    seen: dict[str, dict] = {}
    for ex in all_ex:
        seen[ex["text"]] = ex
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
