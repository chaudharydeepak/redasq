"""
Augment intent classification training data for more diversity.

Two complementary strategies:
  1. nlpaug — fast synonym + contextual word replacement (10x multiplier)
  2. Ollama LLM — paraphrasing for higher-quality variations (slower)

We deliberately avoid augmenting positive examples too aggressively (which could
accidentally remove the entity that justifies the label). For each input:
  - Negative (no labels): aggressive augmentation, label stays []
  - Positive: gentler augmentation that preserves entity-anchor words

Outputs: intent_data_augmented.jsonl
Combine with combine_intent_data.py output via combine_with_augmented.py.
"""
import argparse
import json
import random
import re
import time
from collections import Counter
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

INPUT_PATH = Path(__file__).parent / "intent_data_combined.jsonl"
OUTPUT_PATH = Path(__file__).parent / "intent_data_augmented.jsonl"
SEED = 42

# Words that anchor entity types — we avoid augmenting these to keep labels valid.
ANCHOR_WORDS = {
    "password", "passwd", "pwd", "secret", "key", "token", "credential",
    "email", "ssn", "social", "card", "credit", "ip", "host", "hostname",
    "database", "db", "url", "connection", "ssh", "scp", "rsync", "pem",
    "rsa", "ed25519", "jwt", "bearer", "auth", "api", "aws", "github",
    "openai", "anthropic", "stripe", "redis", "postgres", "mysql", "mongo",
}


def has_anchor_word(text: str) -> bool:
    return any(w in text.lower().split() for w in ANCHOR_WORDS)


# ─── nlpaug-based augmentation ───────────────────────────────────────────────
class NlpAugAugmenter:
    def __init__(self):
        import nlpaug.augmenter.word as naw
        self.synonym = naw.SynonymAug(aug_src="wordnet", aug_min=1, aug_max=3, aug_p=0.2)
        # Spelling errors (typos) — useful for negative examples mostly
        self.spelling = naw.SpellingAug(aug_min=1, aug_max=2, aug_p=0.1)
        # Random word swap — preserves vocabulary
        self.random_swap = naw.RandomWordAug(action="swap", aug_min=1, aug_max=2, aug_p=0.1)

    def augment(self, text: str, n: int = 3) -> list[str]:
        out = set()
        attempts = 0
        while len(out) < n and attempts < n * 3:
            attempts += 1
            try:
                strategy = random.choice(["synonym", "spelling", "swap"])
                if strategy == "synonym":
                    aug_text = self.synonym.augment(text, n=1)[0]
                elif strategy == "spelling":
                    aug_text = self.spelling.augment(text, n=1)[0]
                else:
                    aug_text = self.random_swap.augment(text, n=1)[0]
                if aug_text and aug_text != text:
                    out.add(aug_text)
            except Exception:
                continue
        return list(out)


# ─── Ollama-based paraphrasing ───────────────────────────────────────────────
class OllamaParaphraser:
    def __init__(self, model: str = "llama3:8b", url: str = "http://localhost:11434/api/chat"):
        self.model = model
        self.url = url

    def reachable(self) -> bool:
        try:
            urlopen("http://localhost:11434/api/tags", timeout=2).read()
            return True
        except (URLError, OSError):
            return False

    def paraphrase(self, text: str, n: int = 3) -> list[str]:
        prompt = (
            f"Generate {n} different ways to express this exact same meaning. "
            f"Keep any quoted strings, code, hostnames, IP addresses, and email "
            f"addresses EXACTLY as they appear. Output one paraphrase per line, "
            f"no numbering, no explanations.\n\n"
            f"Original: {text}"
        )
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0.7},
        }
        try:
            req = Request(self.url, data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=120).read()
            content = json.loads(resp).get("message", {}).get("content", "")
            lines = [l.strip().lstrip("-•0123456789. )") for l in content.split("\n")]
            return [l for l in lines if l and l != text and len(l) > 10][:n]
        except Exception as e:
            print(f"  ollama error: {e}")
            return []


# ─── Main pipeline ───────────────────────────────────────────────────────────
def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nlpaug-multiplier", type=int, default=2,
                        help="Number of nlpaug augmentations per source example")
    parser.add_argument("--ollama-fraction", type=float, default=0.05,
                        help="Fraction of positives to paraphrase via Ollama (0-1)")
    parser.add_argument("--ollama-per-example", type=int, default=2,
                        help="Number of Ollama paraphrases per selected example")
    parser.add_argument("--no-ollama", action="store_true",
                        help="Skip Ollama paraphrasing (faster, less variety)")
    parser.add_argument("--max-ollama-examples", type=int, default=300,
                        help="Cap on Ollama-paraphrased source examples (latency control)")
    args = parser.parse_args()

    random.seed(SEED)
    data = load(INPUT_PATH)
    print(f"Loaded {len(data)} source examples from {INPUT_PATH}\n")

    print("Initializing nlpaug...")
    nlp_aug = NlpAugAugmenter()
    print("nlpaug ready.\n")

    use_ollama = not args.no_ollama
    if use_ollama:
        print("Probing Ollama...")
        ollama = OllamaParaphraser()
        if not ollama.reachable():
            print("  Ollama not reachable — disabling LLM paraphrasing.")
            use_ollama = False
        else:
            print(f"  Ollama ready ({ollama.model})\n")

    augmented: list[dict] = []
    seen_text: set[str] = {ex["text"] for ex in data}

    # 1. nlpaug augmentation (fast, every example).
    print(f"Running nlpaug ({args.nlpaug_multiplier}x per example)...")
    t0 = time.monotonic()
    for i, ex in enumerate(data):
        for variant in nlp_aug.augment(ex["text"], n=args.nlpaug_multiplier):
            if variant in seen_text:
                continue
            seen_text.add(variant)
            augmented.append({"text": variant, "labels": ex["labels"]})
        if (i + 1) % 500 == 0:
            elapsed = time.monotonic() - t0
            print(f"  {i+1}/{len(data)}  elapsed={elapsed:.0f}s  augmented={len(augmented)}")
    print(f"nlpaug done in {time.monotonic()-t0:.0f}s — {len(augmented)} new examples\n")

    # 2. Ollama paraphrasing on a sampled subset of positive examples.
    if use_ollama:
        positives = [ex for ex in data if ex["labels"]]
        n_to_paraphrase = min(
            int(len(positives) * args.ollama_fraction),
            args.max_ollama_examples,
        )
        sampled = random.sample(positives, n_to_paraphrase) if n_to_paraphrase else []
        print(f"Running Ollama paraphrasing on {len(sampled)} positive examples...")
        t0 = time.monotonic()
        for i, ex in enumerate(sampled):
            for variant in ollama.paraphrase(ex["text"], n=args.ollama_per_example):
                if variant in seen_text:
                    continue
                seen_text.add(variant)
                augmented.append({"text": variant, "labels": ex["labels"]})
            if (i + 1) % 25 == 0:
                elapsed = time.monotonic() - t0
                rate = (i + 1) / elapsed
                eta = (len(sampled) - i - 1) / max(rate, 0.01)
                print(f"  {i+1}/{len(sampled)}  rate={rate:.2f}/s  ETA={eta:.0f}s")
        print(f"Ollama done in {time.monotonic()-t0:.0f}s\n")

    # 3. Write augmented examples.
    with OUTPUT_PATH.open("w") as f:
        for ex in augmented:
            f.write(json.dumps(ex) + "\n")

    print(f"Wrote {len(augmented)} augmented examples → {OUTPUT_PATH}\n")
    counter = Counter()
    none_count = 0
    for ex in augmented:
        if not ex["labels"]:
            none_count += 1
        for l in ex["labels"]:
            counter[l] += 1
    print("Augmented label frequency:")
    print(f"  no labels (negative): {none_count}")
    for l, n in counter.most_common():
        print(f"  {l:25s} {n}")


if __name__ == "__main__":
    main()
