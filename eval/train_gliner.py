"""
Fine-tune GLiNER on synthetic redasq training data using the built-in Trainer.

Auto-detects GPU. Designed for EC2 GPU training but works on CPU too.
"""
import json
import random
from pathlib import Path

import torch
from gliner import GLiNER

DATA_PATH = Path(__file__).parent / "training_data_v2.json"  # combined pos+neg
OUTPUT_DIR = Path(__file__).parent / "gliner_redasq_v2"
BASE_MODEL = "urchade/gliner_multi-v2.1"

EPOCHS = 5
BATCH_SIZE = 16
LEARNING_RATE = 5e-5
WEIGHT_DECAY = 0.01
EVAL_FRACTION = 0.05
SEED = 42


def main() -> None:
    random.seed(SEED)
    torch.manual_seed(SEED)

    device = (
        "cuda" if torch.cuda.is_available()
        else "mps" if hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
        else "cpu"
    )
    print(f"Device: {device}")

    raw = json.loads(DATA_PATH.read_text())
    print(f"Loaded {len(raw)} examples")

    random.shuffle(raw)
    split = int(len(raw) * (1 - EVAL_FRACTION))
    train_data, eval_data = raw[:split], raw[split:]
    print(f"Train: {len(train_data)}  Eval: {len(eval_data)}")

    print(f"Loading base model {BASE_MODEL}...")
    model = GLiNER.from_pretrained(BASE_MODEL)
    model.to(device)

    # Use GLiNER's built-in Trainer (HuggingFace Trainer wrapper).
    from gliner.training import Trainer, TrainingArguments
    from gliner.data_processing.collator import BiEncoderSpanDataCollator

    args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=EPOCHS,
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        weight_decay=WEIGHT_DECAY,
        warmup_ratio=0.1,
        save_strategy="epoch",
        save_total_limit=1,
        logging_steps=50,
        report_to="none",
        fp16=(device == "cuda"),
        dataloader_num_workers=0,
        remove_unused_columns=False,
    )

    # GLiNER multi-v2.1 is a bi-encoder span model — use its specific collator.
    data_collator = BiEncoderSpanDataCollator(
        model.config,
        data_processor=model.data_processor,
        prepare_labels=True,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_data,
        eval_dataset=eval_data,
        data_collator=data_collator,
    )

    trainer.train()
    model.save_pretrained(str(OUTPUT_DIR))
    print(f"\nSaved fine-tuned model to {OUTPUT_DIR}")

    # Quick eval
    print("\nSample predictions:")
    model.eval()
    labels = sorted({ner[2] for ex in raw for ner in ex["ner"] if ex["ner"]})
    for ex in eval_data[:10]:
        text = " ".join(ex["tokenized_text"])
        truth = [(ex["tokenized_text"][s:e+1], lbl) for s, e, lbl in ex["ner"]]
        pred = model.predict_entities(text, labels, threshold=0.5)
        print(f"  text: {text[:100]}")
        print(f"  truth: {truth}")
        print(f"  pred:  {[(p['text'], p['label'], round(p['score'],2)) for p in pred]}")
        print()


if __name__ == "__main__":
    main()
