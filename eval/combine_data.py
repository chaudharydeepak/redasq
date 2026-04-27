"""
Combine positives (training_data.json) + negatives (negatives.json)
into a single shuffled training set: training_data_v2.json.
"""
import json
import random
from pathlib import Path

POS = Path(__file__).parent / "training_data.json"
NEG = Path(__file__).parent / "negatives.json"
OUT = Path(__file__).parent / "training_data_v2.json"

random.seed(42)
positives = json.loads(POS.read_text())
negatives = json.loads(NEG.read_text())
all_examples = positives + negatives
random.shuffle(all_examples)
OUT.write_text(json.dumps(all_examples))
print(f"Positives: {len(positives)}")
print(f"Negatives: {len(negatives)}")
print(f"Combined:  {len(all_examples)} → {OUT}")
