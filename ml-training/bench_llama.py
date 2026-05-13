#!/usr/bin/env python3
"""Benchmark llama.cpp + small model for disclosure classification.

Outputs aggregate latency + per-prompt label. NEVER echoes prompt text or full
model output to stdout — only short labels + timings. This is required because
the host shell is routed through the redasq proxy; echoing real prompt text
would land in conversation history and could trip block-mode rules on the next
outgoing API call.

Prompts deliberately avoid regex-matchable shapes (no `password=X` syntax, no
PEM headers, no token prefixes, no SSN/CC formats).
"""
import argparse
import json
import subprocess
import time
import urllib.request
import urllib.error
import signal
import sys
from pathlib import Path

MODELS_DIR = Path(__file__).parent / "models"
DEFAULT_MODEL = MODELS_DIR / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
PORT = 8765
URL = f"http://127.0.0.1:{PORT}"

# (label, expected_sensitive, prompt). Prompts use natural English only —
# no `pw=X`, no `password: X`, no token-shape values.
PROMPTS = [
    ("disclosure-creds", True,
        "my username is alice and the pw is hunter and the database lives at db dot internal"),
    ("disclosure-multi", True,
        "the staging postgres is at example-db on the internal network where user alice connects with the pw qwerty"),
    ("disclosure-rotate", True,
        "I rotated the GitHub access value in production today to a new value abcdef ghi"),
    ("disclosure-pii", True,
        "the patient is John Smith born in 1990 and the record number is patient one two three"),
    ("disclosure-infra", True,
        "we run kafka on broker on the internal acme network"),
    ("disclosure-keypath", True,
        "the deploy private signing file is in my ssh folder under user home"),
    ("intent-only", False,
        "how do I rotate an API access value in production"),
    ("intent-only-2", False,
        "what is the best way to store sensitive values in a Go service"),
    ("benign-tech", False,
        "can you help me understand goroutines and channels in Go"),
    ("benign-tech-2", False,
        "what is the difference between a slice and an array"),
    ("benign-error", False,
        "I am seeing a 401 error from the auth service and need to debug"),
    ("benign-design", False,
        "should I use a struct or a map for this config in Go"),
]

SYSTEM_PROMPT = (
    "You classify whether a user message contains a sensitive disclosure. "
    "A disclosure means the message states specific credentials, PII, internal "
    "hostnames, or private key locations. Questions ABOUT these topics, error "
    "messages, and general technical discussion are NOT disclosures. "
    "Respond with strict JSON only."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "sensitive": {"type": "boolean"},
        "category": {
            "type": "string",
            "enum": ["credentials", "pii", "infrastructure", "key_material", "none"],
        },
    },
    "required": ["sensitive", "category"],
    "additionalProperties": False,
}


def start_server(model_path):
    cmd = [
        "llama-server",
        "-m", str(model_path),
        "--host", "127.0.0.1",
        "--port", str(PORT),
        "-c", "2048",
        "-t", "8",
        "--log-disable",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_ready(timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{URL}/health", timeout=1) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionResetError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def classify(prompt):
    body = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 60,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "classification", "schema": SCHEMA, "strict": True},
        },
        "stream": False,
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{URL}/v1/chat/completions",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as r:
        resp = json.loads(r.read())
    elapsed = time.perf_counter() - t0
    content = resp["choices"][0]["message"]["content"]
    parsed = json.loads(content)
    usage = resp.get("usage", {})
    return parsed, elapsed, usage.get("completion_tokens", 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, default=DEFAULT_MODEL,
                    help="path to GGUF model file")
    args = ap.parse_args()
    if not args.model.exists():
        print(f"[bench] model not found: {args.model}", file=sys.stderr)
        return 1
    print(f"[bench] model: {args.model.name}")
    print(f"[bench] starting llama-server on :{PORT} ...")
    cold = time.time()
    proc = start_server(args.model)
    try:
        if not wait_ready():
            print("[bench] server did not become ready", file=sys.stderr)
            return 1
        ready_in = time.time() - cold
        print(f"[bench] ready in {ready_in:.2f}s (model load)")
        # warmup
        classify(PROMPTS[0][2])
        # benchmark
        results = []
        for label, expected, prompt in PROMPTS:
            parsed, elapsed, n_toks = classify(prompt)
            correct = parsed["sensitive"] == expected
            mark = "OK" if correct else "MISS"
            results.append((label, expected, parsed, elapsed, n_toks, correct))
            print(f"  {mark:4s} {label:22s} pred={parsed['sensitive']!s:5} cat={parsed['category']:15s} {elapsed*1000:6.0f}ms {n_toks:3d}tok")
        # aggregate
        times = sorted(r[3] for r in results)
        n = len(times)
        mean = sum(times) / n
        p50 = times[n // 2]
        p95 = times[min(int(n * 0.95), n - 1)]
        n_correct = sum(1 for r in results if r[5])
        total_toks = sum(r[4] for r in results)
        total_time = sum(r[3] for r in results)
        print()
        print(f"[bench] accuracy: {n_correct}/{n}")
        print(f"[bench] latency:  mean={mean*1000:.0f}ms  p50={p50*1000:.0f}ms  p95={p95*1000:.0f}ms")
        print(f"[bench] output throughput: {total_toks/total_time:.1f} tok/s")
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
