"""
Combine the original combined data + augmented data into a single training file.
"""
import json
import random
from collections import Counter
from pathlib import Path

ORIG = Path(__file__).parent / "intent_data_combined.jsonl"
AUG = Path(__file__).parent / "intent_data_augmented.jsonl"
OUT = Path(__file__).parent / "intent_data_v2.jsonl"

random.seed(42)


def load(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    orig = load(ORIG)
    aug = load(AUG)
    all_ex = orig + aug
    random.shuffle(all_ex)
    with OUT.open("w") as f:
        for ex in all_ex:
            f.write(json.dumps(ex) + "\n")

    print(f"Original:  {len(orig)}")
    print(f"Augmented: {len(aug)}")
    print(f"Total v2:  {len(all_ex)} → {OUT}\n")

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
