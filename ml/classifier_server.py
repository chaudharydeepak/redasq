"""
DistilBERT intent classifier sidecar for redasq.

Loads the quantized ONNX model + HuggingFace tokenizer once at startup and
serves POST /classify. Returns per-label sigmoid probabilities, the labels
above their per-intent threshold, and the top label/score. The Go proxy
calls this in parallel with the regex inspection pass; predictions are
stored alongside each prompt for UI display.

This is OPINION-ONLY — predictions never influence block/redact decisions
in the current architecture.
"""
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer

# Prefer the newest converted ONNX model present in eval/. v5 wins over v4
# automatically once the user copies it over from EC2 — no flag flip needed.
EVAL_DIR = Path(__file__).resolve().parent.parent / "eval"
_VERSION_PREFERENCE = ["distilbert_redasq_v6_onnx", "distilbert_redasq_v5_onnx", "distilbert_redasq_v4_onnx"]
DEFAULT_MODEL_DIR = next(
    (EVAL_DIR / v for v in _VERSION_PREFERENCE if (EVAL_DIR / v / "model.onnx").exists()),
    EVAL_DIR / _VERSION_PREFERENCE[-1],  # fall back to v4 path even if missing — let load fail loudly
)
MODEL_DIR = Path(os.environ.get("REDASQ_MODEL_DIR", str(DEFAULT_MODEL_DIR)))

_state: dict[str, Any] = {}


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = json.loads((MODEL_DIR / "redasq_config.json").read_text())
    print(f"loading classifier from {MODEL_DIR}...", flush=True)
    session = ort.InferenceSession(
        str(MODEL_DIR / "model.onnx"),
        providers=["CPUExecutionProvider"],
    )
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    _state["session"] = session
    _state["tokenizer"] = tokenizer
    _state["labels"] = cfg["labels"]
    _state["thresholds"] = cfg.get("thresholds", {})
    _state["max_length"] = cfg.get("max_length", 512)
    _state["model_name"] = cfg.get("model_name", MODEL_DIR.name)
    print(f"classifier ready ({_state['model_name']}, {len(cfg['labels'])} labels)", flush=True)
    yield
    _state.clear()


app = FastAPI(lifespan=lifespan)


class ClassifyRequest(BaseModel):
    text: str


class ClassifyResponse(BaseModel):
    scores: dict[str, float]
    above_threshold: list[str]
    top_label: str
    top_score: float
    latency_ms: int


@app.get("/health")
def health() -> dict[str, Any]:
    if "session" not in _state:
        return {"status": "loading"}
    return {
        "status": "ok",
        "model": _state.get("model_name", MODEL_DIR.name),
        "labels": _state.get("labels", []),
    }


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest) -> ClassifyResponse:
    if "session" not in _state:
        return ClassifyResponse(
            scores={}, above_threshold=[], top_label="", top_score=0.0, latency_ms=0
        )

    session: ort.InferenceSession = _state["session"]
    tokenizer = _state["tokenizer"]
    labels: list[str] = _state["labels"]
    thresholds: dict[str, float] = _state["thresholds"]
    max_length: int = _state["max_length"]

    t0 = time.monotonic()
    enc = tokenizer(
        req.text,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_tensors="np",
    )
    feeds = {
        "input_ids": enc["input_ids"].astype(np.int64),
        "attention_mask": enc["attention_mask"].astype(np.int64),
    }
    logits = session.run(["logits"], feeds)[0]
    probs = _sigmoid(logits)[0]
    latency_ms = int((time.monotonic() - t0) * 1000)

    scores = {label: float(probs[i]) for i, label in enumerate(labels)}
    above = [
        label
        for label, score in scores.items()
        if score >= thresholds.get(label, 0.5)
    ]
    top_idx = int(np.argmax(probs))
    return ClassifyResponse(
        scores=scores,
        above_threshold=above,
        top_label=labels[top_idx],
        top_score=float(probs[top_idx]),
        latency_ms=latency_ms,
    )
