"""
GLiNER detection service for redasq.

Wraps GLiNER in a small FastAPI service. redasq calls POST /detect with text;
service returns labeled spans with confidence scores. Validation and
block/track decisions stay in redasq (Go side).
"""
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

# Default labels — curated for credentials + infrastructure leakage.
# Can be overridden per-request.
DEFAULT_LABELS = [
    "password",
    "api key",
    "secret token",
    "private ssh key",
    "username",
    "internal hostname",
    "internal ip address",
    "database connection string",
    "personal email address",
    "phone number",
    "credit card number",
    "social security number",
    "AWS access key id",
    "github personal access token",
]

DEFAULT_THRESHOLD = float(os.environ.get("ML_THRESHOLD", "0.55"))
MODEL_NAME = os.environ.get("ML_MODEL", "urchade/gliner_multi-v2.1")

# Global model instance — loaded once at startup.
_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    from gliner import GLiNER
    print(f"loading {MODEL_NAME}...", flush=True)
    _state["model"] = GLiNER.from_pretrained(MODEL_NAME)
    print("model ready", flush=True)
    yield
    _state.clear()


app = FastAPI(lifespan=lifespan)


class DetectRequest(BaseModel):
    text: str
    labels: list[str] | None = None
    threshold: float | None = None


class Entity(BaseModel):
    text: str
    label: str
    score: float
    start: int
    end: int


class DetectResponse(BaseModel):
    entities: list[Entity]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok" if "model" in _state else "loading"}


@app.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest) -> DetectResponse:
    if "model" not in _state:
        return DetectResponse(entities=[])
    labels = req.labels or DEFAULT_LABELS
    threshold = req.threshold if req.threshold is not None else DEFAULT_THRESHOLD
    raw = _state["model"].predict_entities(req.text, labels, threshold=threshold)
    return DetectResponse(
        entities=[
            Entity(text=e["text"], label=e["label"], score=float(e["score"]), start=e["start"], end=e["end"])
            for e in raw
        ]
    )
