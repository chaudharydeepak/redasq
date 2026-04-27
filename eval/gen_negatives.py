"""
Generate negative training examples that target the hallucination patterns
we observed in eval_full_db.py results.

These are texts that LOOK identifier-y or technical but contain NO sensitive
data the model should tag. By training on these as `ner: []`, we teach the
model what's NOT a secret.

Outputs: negatives.json — combine with training_data.json before retraining.
"""
import json
import random
import string
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "negatives.json"
RANDOM_SEED = 99
random.seed(RANDOM_SEED)


def hex_string(length: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))


def alnum(length: int, charset: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choices(charset, k=length))


# ── Patterns the model wrongly tagged in our eval ────────────────────────────

GIT_HASHES_LONG = [hex_string(40) for _ in range(50)]
GIT_HASHES_SHORT = [hex_string(7) for _ in range(50)]
UUIDS = [
    f"{hex_string(8)}-{hex_string(4)}-{hex_string(4)}-{hex_string(4)}-{hex_string(12)}"
    for _ in range(80)
]

TIMESTAMPS = []
for _ in range(60):
    yr = random.randint(2024, 2027)
    mo, d = random.randint(1, 12), random.randint(1, 28)
    hh, mm, ss = random.randint(0, 23), random.randint(0, 59), random.randint(0, 59)
    ms = random.randint(0, 999)
    TIMESTAMPS.extend([
        f"{yr}-{mo:02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}.{ms:03d}Z",
        f"{yr}/{mo:02d}/{d:02d} {hh:02d}:{mm:02d}:{ss:02d}",
        f"{yr}-{mo:02d}-{d:02d} {hh:02d}:{mm:02d}",
    ])

DATES = []
months = ["January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December"]
for _ in range(40):
    DATES.append(f"{random.choice(months)} {random.randint(1, 28)}, {random.randint(2024, 2027)}")

VERSIONS = [
    f"v{random.randint(0, 24)}.{random.randint(0, 30)}.{random.randint(0, 99)}"
    for _ in range(60)
] + [
    f"{random.randint(0, 24)}.{random.randint(0, 30)}.{random.randint(0, 99)}"
    for _ in range(40)
]

PORTS = ["3000", "8080", "8443", "5432", "3306", "6379", "27017", "9090",
         "9091", "5000", "5001", "7778", "11434"]

ARCHS = ["x64", "x86_64", "arm64", "aarch64", "amd64", "i386", "armv7"]

CODE_IDENTIFIERS = [
    "extractTelemetryInfo", "tlsClient", "ExtractPrompts", "ExtractUserQuery",
    "debugf", "stripPort", "isTelemetry", "ParseRequest", "InspectAndStore",
    "writeBlockedResponse", "RedactBodyForForwarding", "SavePrompt",
    "loadCA", "issueCert", "matchSuffix", "handleConnect",
    "user_id", "session_id", "device_id", "client_id", "request_id",
    "todos", "todo_deps", "users_v2", "events_log", "audit_trail",
    "buf.Bytes", "io.Copy", "json.Marshal", "context.Background",
    "make([]byte", "len(body)", "string(body)", "req.URL.Path",
]

HTTP_HEADERS = [
    "X-Session-Id", "X-Vscode-Session-Id", "Vscode-Sessionid",
    "X-Client-Session-Id", "X-Github-Session-Id", "Copilot-Integration-Id",
    "X-Request-Id", "User-Agent", "Content-Type", "Accept",
    "Authorization", "X-Forwarded-For", "X-Real-IP", "Cookie",
    "X-Github-Api-Version", "X-Anthropic-Version",
]

URLS_NO_CREDS = [
    "https://github.com/chaudharydeepak/redasq",
    "https://github.com/chaudharydeepak/prompt-guard",
    "https://api.anthropic.com/v1/messages",
    "https://api.openai.com/v1/chat/completions",
    "https://api.individual.githubcopilot.com/chat/completions",
    "http://localhost:7778/api/prompts",
    "http://localhost:8080",
    "https://docs.anthropic.com",
    "https://huggingface.co/urchade/gliner_multi-v2.1",
    "/usr/local/Cellar/redasq",
    "/Users/dev/projects/redasq/main.go",
]

TYPOS_AND_WORDS = [
    "dahsbaord", "dahabosr", "deifnitley", "wihtou", "lollama", "copiit",
    "becuase", "recieve", "occured", "seperate", "untill", "definately",
]

BUILD_OUTPUT_LINES = [
    "==> Updating Homebrew...",
    "Updated 1 tap (chaudharydeepak/tap).",
    "remote: Bypassed rule violations for refs/heads/master:",
    "Fast-forward",
    "1 file changed, 1 insertion(+), 1 deletion(-)",
    "Adjust how often this is run with HOMEBREW_AUTO_UPDATE_SECS",
    "[master 66e1526] fix: restore selective header logging",
    "Successfully built abc123",
    "Step 1/8 : FROM golang:1.22",
    "Removing intermediate container abc1234",
]


# ── Templates that wrap noise into realistic prompt-like text ────────────────

NOISE_TEMPLATES = [
    # Git/commit context
    "[master {hash}] fix: update logging behavior",
    "[main {hash}] feat: add new endpoint",
    "remote: To https://github.com/chaudharydeepak/redasq.git\n   {hash}..{hash} master -> master",
    "commit {long_hash}\nAuthor: dev\nDate: {date}\n\n    fix: handle edge case",
    "Fast-forward\n {hash}..{hash}",
    # Timestamps in logs
    "{ts} INFO server started on port {port}",
    "{ts} hello copilot cli No tables currently exist. Default tables ({code1}, {code2}) will be created automatically",
    "{ts} REQUEST: POST api.anthropic.com/v1/messages body=12345 bytes stream=true",
    "{ts} HEADER {header}: value-here",
    # Version + arch
    "Build version {version} for {arch}",
    "Running on Node.js {version} {arch}",
    "redasq {version} ({arch})",
    "Updated to {version}",
    # Code snippets
    "func {code1}(body []byte) string {{ return {code2}(body) }}",
    "{code1}.{code2}({code1}, {code2})",
    "// {code1} handles the {code2} request",
    "Called the Read tool with input: {{\"file_path\":\"/Users/dev/{code1}.go\"}}",
    "{code1} := {code2}(req.URL.Path)",
    "if {code1} == nil {{ return {code2} }}",
    "{header}: {code1}-{code2}-{hash}",
    # Header lists
    "for _, h := range []string{{\"{header}\", \"{header}\", \"{header}\"}}",
    "request headers: {header}, {header}, {header}",
    # URLs without creds
    "GET {url}",
    "Fetched {url} successfully",
    "see {url} for details",
    # Conversational with typos
    "i think {typo} is the issue",
    "the {typo} is on the dashboard",
    "{typo} this works as expected",
    # UUIDs (session IDs, machine IDs)
    "session_id: {uuid}",
    "machine id is {uuid}",
    "X-Client-Machine-Id: {uuid}",
    "request_id={uuid}",
    "device_id: {uuid}",
    # Build/install output
    "{build}",
    "{build}\n{build}",
    # Combinations
    "{ts} {build}",
    "log entry {ts} commit {hash} version {version}",
    "{header}: {uuid}",
    "[{hash}] commit by dev on {date}",
]


def fill_template(template: str) -> str:
    """Fill template placeholders with random noise values."""
    return template.format(
        hash=random.choice(GIT_HASHES_SHORT),
        long_hash=random.choice(GIT_HASHES_LONG),
        ts=random.choice(TIMESTAMPS),
        date=random.choice(DATES),
        version=random.choice(VERSIONS),
        arch=random.choice(ARCHS),
        port=random.choice(PORTS),
        code1=random.choice(CODE_IDENTIFIERS),
        code2=random.choice(CODE_IDENTIFIERS),
        header=random.choice(HTTP_HEADERS),
        url=random.choice(URLS_NO_CREDS),
        typo=random.choice(TYPOS_AND_WORDS),
        uuid=random.choice(UUIDS),
        build=random.choice(BUILD_OUTPUT_LINES),
    )


def main() -> None:
    examples: list[dict] = []
    seen = set()

    # 1. Generate noise from templates.
    target = 8000
    attempts = 0
    while len(examples) < target and attempts < target * 3:
        attempts += 1
        template = random.choice(NOISE_TEMPLATES)
        try:
            text = fill_template(template)
        except (KeyError, IndexError):
            continue
        if text in seen:
            continue
        seen.add(text)
        examples.append({"tokenized_text": text.split(), "ner": []})

    # 2. Bare strings that the model wrongly tagged at 1.0 confidence.
    bare_strings = (
        GIT_HASHES_LONG + GIT_HASHES_SHORT + UUIDS[:50] + TIMESTAMPS[:40]
        + DATES[:30] + VERSIONS[:50] + PORTS + ARCHS + CODE_IDENTIFIERS
        + HTTP_HEADERS + TYPOS_AND_WORDS
    )
    for s in bare_strings:
        if s not in seen:
            examples.append({"tokenized_text": s.split(), "ner": []})
            seen.add(s)

    # 3. Conversational sentences with no entity (typos, code refs, dev chat).
    conv_negatives = [
        "i need to debug the session id thing",
        "what is the difference between copilot cli and claude cli",
        "the dashboard shows no tables yet",
        "rebuilding and restarting the proxy",
        "let me check the config file again",
        "git push is failing — looks like a permission thing",
        "the build worked but tests are flaky",
        "trying to figure out why the request is timing out",
        "lets refactor the inspector engine module",
        "i think the regex pattern is too broad",
        "we should add more negative test cases",
        "the function ExtractPrompts is doing too much",
        "checking the logs for the failed deploy",
        "vscode shows the file but it's empty",
        "running on macos with python 3.11",
        "uploaded the model and started training",
        "the gpu instance is up and running",
        "lets try with a higher learning rate next time",
        "the loss is not decreasing as expected",
        "model checkpoint failed because disk is full",
    ]
    for s in conv_negatives:
        if s not in seen:
            examples.append({"tokenized_text": s.split(), "ner": []})
            seen.add(s)

    random.shuffle(examples)
    OUTPUT_PATH.write_text(json.dumps(examples))
    print(f"Wrote {len(examples)} negative examples to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
