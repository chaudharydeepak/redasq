"""
Evaluate a local LLM (via Ollama) as a sensitive-data detector for redasq.

Pulls sample prompts from ~/.redasq/redasq.db, sends each to the LLM with a
security-scanner system prompt, parses structured JSON findings, and prints
results alongside what redasq's regex rules already caught.
"""
import json
import sqlite3
import sys
import textwrap
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

DB_PATH = Path.home() / ".redasq" / "redasq.db"
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3:8b"
SAMPLE_PER_STATUS = 3   # keep small — 8B model is ~15-30s per prompt on CPU
MAX_PROMPT_CHARS = 2000

SYSTEM_PROMPT = """\
You are a security scanner that protects users from leaking sensitive data \
to third-party LLMs. Analyze the provided text and identify any sensitive values.

Categories to detect:
- credentials: passwords, API keys, tokens, secrets, OAuth tokens
- infrastructure: database hostnames, internal IPs, server addresses, connection strings
- keys: SSH private keys, certificates, key file paths
- pii: emails, phone numbers, SSNs, credit cards, full names with context
- internal: internal-only URLs, hostnames ending in .local/.internal/.corp

Return ONLY valid JSON in this exact shape:
{"findings": [{"type": "<category>", "value": "<exact substring>", "reason": "<why sensitive>"}]}

Rules:
- Report only values actually present in the text. Do not invent or hallucinate.
- "value" must be the exact substring as it appears in the text.
- If nothing sensitive, return {"findings": []}.
- Do not include explanations outside the JSON.
"""


def load_samples(db_path: Path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    samples = []
    for status in ("clean", "redacted", "blocked"):
        cur.execute(
            "SELECT id, status, prompt, matches FROM prompts "
            "WHERE status = ? AND length(prompt) > 50 AND length(prompt) < 5000 "
            "ORDER BY id DESC LIMIT ?",
            (status, SAMPLE_PER_STATUS),
        )
        samples.extend(cur.fetchall())
    conn.close()
    return samples


def fmt_existing_matches(matches_json: str) -> str:
    if not matches_json:
        return "—"
    try:
        matches = json.loads(matches_json)
    except json.JSONDecodeError:
        return "?"
    if not matches:
        return "—"
    return ", ".join(m.get("rule_name", "?") for m in matches)


def call_ollama(text: str) -> tuple[list[dict], float]:
    """Send text to Ollama and return parsed findings + latency in seconds."""
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Text to analyze:\n{text}"},
        ],
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.0},
    }
    body = json.dumps(payload).encode()
    req = Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    start = time.monotonic()
    with urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read())
    latency = time.monotonic() - start
    content = data.get("message", {}).get("content", "")
    try:
        parsed = json.loads(content)
        return parsed.get("findings", []), latency
    except json.JSONDecodeError:
        return [{"type": "parse_error", "value": content[:120], "reason": "non-JSON"}], latency


def main() -> None:
    if not DB_PATH.exists():
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    # Probe Ollama availability.
    try:
        urlopen("http://localhost:11434/api/tags", timeout=2).read()
    except URLError as e:
        print(f"Ollama not reachable at localhost:11434 — start it with `ollama serve`. {e}", file=sys.stderr)
        sys.exit(1)

    samples = load_samples(DB_PATH)
    print(f"Model: {MODEL}")
    print(f"Evaluating {len(samples)} prompts ({SAMPLE_PER_STATUS} each from clean/redacted/blocked)\n")

    for row_id, status, prompt, matches_json in samples:
        text = prompt[:MAX_PROMPT_CHARS]
        existing = fmt_existing_matches(matches_json)

        try:
            findings, latency = call_ollama(text)
        except Exception as e:
            print(f"#{row_id} [{status}] ERROR: {e}")
            continue

        if findings:
            findings_summary = "; ".join(
                f"{f.get('type', '?')}={f.get('value', '?')[:60]!r}" for f in findings
            )
        else:
            findings_summary = "—"

        print(f"── #{row_id} [{status}] ({latency:.1f}s) " + "─" * 30)
        print(f"  prompt:   {textwrap.shorten(text, 140)}")
        print(f"  redasq:   {existing}")
        print(f"  llm:      {findings_summary}")
        print()


if __name__ == "__main__":
    main()
