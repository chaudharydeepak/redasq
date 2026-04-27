"""
Combine real DB-derived examples + synthetic examples into one training set.
"""
import json
import random
from collections import Counter
from pathlib import Path

DB_DERIVED = Path(__file__).parent / "intent_data.jsonl"
SYNTHETIC = Path(__file__).parent / "synthetic_intent_data.jsonl"
OUT = Path(__file__).parent / "intent_data_combined.jsonl"

random.seed(42)


def load(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    db = load(DB_DERIVED)
    syn = load(SYNTHETIC)
    all_ex = db + syn
    random.shuffle(all_ex)
    with OUT.open("w") as f:
        for ex in all_ex:
            f.write(json.dumps(ex) + "\n")
    print(f"DB-derived:   {len(db)}")
    print(f"Synthetic:    {len(syn)}")
    print(f"Combined:     {len(all_ex)} → {OUT}\n")
    counter = Counter()
    none_count = 0
    for ex in all_ex:
        if not ex["labels"]:
            none_count += 1
        for l in ex["labels"]:
            counter[l] += 1
    print(f"  no labels (negative):    {none_count}")
    for l, n in counter.most_common():
        print(f"  {l:25s} {n}")


if __name__ == "__main__":
    main()
