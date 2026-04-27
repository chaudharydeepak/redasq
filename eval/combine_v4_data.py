"""
Combine v2 data + targeted negatives → intent_data_v4.jsonl for v4 training.
"""
import json
import random
from collections import Counter
from pathlib import Path

V2 = Path(__file__).parent / "intent_data_v2.jsonl"
TARGETED = Path(__file__).parent / "targeted_negatives.jsonl"
OUT = Path(__file__).parent / "intent_data_v4.jsonl"

random.seed(42)


def load(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    v2 = load(V2)
    targeted = load(TARGETED)
    all_ex = v2 + targeted
    random.shuffle(all_ex)
    with OUT.open("w") as f:
        for ex in all_ex:
            f.write(json.dumps(ex) + "\n")

    print(f"v2 data:           {len(v2)}")
    print(f"Targeted negatives: {len(targeted)}")
    print(f"Combined v4:       {len(all_ex)} → {OUT}\n")

    counter = Counter()
    none_count = 0
    for ex in all_ex:
        if not ex["labels"]:
            none_count += 1
        for l in ex["labels"]:
            counter[l] += 1
    print(f"  no labels (negative):  {none_count}")
    for l, n in counter.most_common():
        print(f"  {l:25s} {n}")


if __name__ == "__main__":
    main()
