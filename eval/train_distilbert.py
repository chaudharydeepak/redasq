"""
Train DistilBERT for multi-label intent classification on redasq prompts.

Inputs: jsonl corpus (one JSON per line: {text, labels: [...]}).
Output: model directory with the fine-tuned weights + tokenizer.

Defaults to v5 corpus / output. Override via env vars or CLI flags:
  REDASQ_DATA=intent_data_v5.jsonl REDASQ_OUTPUT=distilbert_redasq_v5
  python train_distilbert.py --data foo.jsonl --output bar/

Auto-detects GPU. Designed for EC2 GPU but runs on CPU too (slower).
"""
import argparse
import json
import os
import random
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    Trainer, TrainingArguments,
)

ROOT = Path(__file__).parent
DEFAULT_DATA = os.environ.get("REDASQ_DATA", "intent_data_v6.jsonl")
DEFAULT_OUTPUT = os.environ.get("REDASQ_OUTPUT", "distilbert_redasq_v6")
BASE_MODEL = "distilbert-base-uncased"

LABELS = [
    "pii", "infrastructure", "key_material", "auth_token",
    "service_credential", "generic_credential",
]
LABEL_TO_IDX = {l: i for i, l in enumerate(LABELS)}
NUM_LABELS = len(LABELS)

EPOCHS = 5
BATCH_SIZE = 32
LEARNING_RATE = 5e-5
MAX_LENGTH = 512
EVAL_FRACTION = 0.1
SEED = 42


def load_data(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def labels_to_vector(labels: list[str]) -> list[float]:
    """Convert label list → multi-hot vector of length NUM_LABELS."""
    v = [0.0] * NUM_LABELS
    for l in labels:
        if l in LABEL_TO_IDX:
            v[LABEL_TO_IDX[l]] = 1.0
    return v


class IntentDataset(Dataset):
    def __init__(self, examples, tokenizer):
        self.examples = examples
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        ex = self.examples[idx]
        enc = self.tokenizer(
            ex["text"],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(labels_to_vector(ex["labels"]), dtype=torch.float),
        }


def compute_metrics(eval_pred):
    """Per-label P/R/F1 + micro/macro averages."""
    logits, labels = eval_pred
    preds = (torch.sigmoid(torch.tensor(logits)) > 0.5).numpy().astype(int)
    labels = labels.astype(int)

    tp = (preds & labels).sum(axis=0)
    fp = (preds & ~labels).sum(axis=0)
    fn = (~preds & labels).sum(axis=0)

    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / np.maximum(tp + fn, 1)
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-9)

    metrics = {"micro_f1": f1.mean()}
    for i, label in enumerate(LABELS):
        metrics[f"f1_{label}"] = float(f1[i])
        metrics[f"p_{label}"] = float(precision[i])
        metrics[f"r_{label}"] = float(recall[i])
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=DEFAULT_DATA,
                        help="Training jsonl filename (relative to eval/) or absolute path")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="Output directory name (relative to eval/) or absolute path")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.is_absolute():
        data_path = ROOT / data_path
    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir

    random.seed(SEED)
    torch.manual_seed(SEED)

    device = (
        "cuda" if torch.cuda.is_available()
        else "mps" if hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
        else "cpu"
    )
    print(f"Device: {device}")
    print(f"Data:   {data_path}")
    print(f"Output: {output_dir}")

    data = load_data(data_path)
    print(f"Loaded {len(data)} examples")
    random.shuffle(data)
    split = int(len(data) * (1 - EVAL_FRACTION))
    train_data, eval_data = data[:split], data[split:]
    print(f"Train: {len(train_data)}  Eval: {len(eval_data)}")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=NUM_LABELS,
        problem_type="multi_label_classification",
        id2label={i: l for i, l in enumerate(LABELS)},
        label2id=LABEL_TO_IDX,
    )

    train_ds = IntentDataset(train_data, tokenizer)
    eval_ds = IntentDataset(eval_data, tokenizer)

    targs = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        warmup_ratio=0.1,
        weight_decay=0.01,
        logging_steps=50,
        eval_strategy="epoch",
        save_strategy="no",
        report_to="none",
        fp16=(device == "cuda"),
        dataloader_num_workers=2,
        remove_unused_columns=False,
    )

    trainer = Trainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        compute_metrics=compute_metrics,
    )

    trainer.train()

    output_dir.mkdir(exist_ok=True)
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    print(f"\nSaved to {output_dir}")

    # Final eval
    metrics = trainer.evaluate()
    print("\nFinal eval metrics:")
    for k, v in sorted(metrics.items()):
        if isinstance(v, float):
            print(f"  {k:30s} {v:.4f}")


if __name__ == "__main__":
    main()
