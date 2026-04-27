"""
Convert the fine-tuned DistilBERT model to ONNX for Go inference.

Output:
  distilbert_redasq_v4_onnx/
    model.onnx       — quantized ONNX model (~70MB after int8 quantization)
    tokenizer.json   — HF tokenizer (used by Rust tokenizers in Go)
    config.json      — labels, thresholds
    vocab.txt        — tokenizer vocab (fallback)

Quantization: int8 reduces ~250MB FP32 model to ~70MB with negligible accuracy loss.
"""
import argparse
import json
import os
import shutil
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

ROOT = Path(__file__).parent
DEFAULT_MODEL = os.environ.get("REDASQ_MODEL", "distilbert_redasq_v6")
DEFAULT_ONNX_OUT = os.environ.get("REDASQ_ONNX_OUT", "distilbert_redasq_v6_onnx")

LABELS = [
    "pii", "infrastructure", "key_material", "auth_token",
    "service_credential", "generic_credential",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Source PyTorch model dir (relative to eval/) or absolute path")
    parser.add_argument("--output", default=DEFAULT_ONNX_OUT,
                        help="ONNX output dir (relative to eval/) or absolute path")
    args = parser.parse_args()

    MODEL_DIR = Path(args.model) if Path(args.model).is_absolute() else ROOT / args.model
    OUTPUT_DIR = Path(args.output) if Path(args.output).is_absolute() else ROOT / args.output

    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"Loading model from {MODEL_DIR}...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.eval()

    # Dummy input: batch_size=1, seq_len=512
    dummy_input = tokenizer(
        "the password is hunter2", return_tensors="pt",
        padding="max_length", max_length=512, truncation=True,
    )

    print("Exporting to ONNX (FP32)...")
    onnx_fp32_path = OUTPUT_DIR / "model_fp32.onnx"
    torch.onnx.export(
        model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        str(onnx_fp32_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "sequence_length"},
            "attention_mask": {0: "batch_size", 1: "sequence_length"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
        do_constant_folding=True,
    )
    fp32_size = onnx_fp32_path.stat().st_size / 1024 / 1024
    print(f"  FP32 model: {fp32_size:.1f} MB")

    # INT8 quantization for production deployment.
    print("\nApplying INT8 dynamic quantization...")
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
        onnx_int8_path = OUTPUT_DIR / "model.onnx"
        quantize_dynamic(
            str(onnx_fp32_path),
            str(onnx_int8_path),
            weight_type=QuantType.QInt8,
        )
        int8_size = onnx_int8_path.stat().st_size / 1024 / 1024
        print(f"  INT8 model: {int8_size:.1f} MB ({100*int8_size/fp32_size:.0f}% of FP32)")
        # Remove FP32 to save space
        onnx_fp32_path.unlink()
    except ImportError:
        print("  onnxruntime not installed — skipping quantization (run: pip install onnxruntime)")
        onnx_fp32_path.rename(OUTPUT_DIR / "model.onnx")

    # Save tokenizer + config for Go to use.
    print("\nSaving tokenizer...")
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    # Write a simple inference config for Go.
    config = {
        "model_name": MODEL_DIR.name,
        "labels": LABELS,
        "max_length": 512,
        # Per-category thresholds tuned from eval
        "thresholds": {
            "pii": 0.90,
            "infrastructure": 0.85,
            "key_material": 0.85,
            "auth_token": 0.85,
            "service_credential": 0.90,
            "generic_credential": 0.95,
        },
    }
    (OUTPUT_DIR / "redasq_config.json").write_text(json.dumps(config, indent=2))

    print(f"\nDone. Output:")
    for f in sorted(OUTPUT_DIR.iterdir()):
        size = f.stat().st_size / 1024
        print(f"  {f.name:30s} {size:>10.1f} KB")


if __name__ == "__main__":
    main()
