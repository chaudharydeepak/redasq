"""
Generate v5 training data from real false-positive / true-positive patterns
observed while debugging redasq's intent classifier in production.

Categories addressed:

NEGATIVES (currently over-firing — need labels: []):
  N1. Meta-discussion of the classifier itself
      ("why does this row classify as ...", "the rule fired on ...")
  N2. CLI tool mentions without any credential value
      ("let me try this with copilot cli", "running the gh CLI")
  N3. Build / dev chat using security-domain vocabulary
      ("the auth_token rule fired on this prompt")
  N4. Short conversational acknowledgements
      ("started", "ok just restarted", "looks good")
  N5. Tool / file references describing locations, not content
      ("see the config at ~/.aws/config", "open ~/Downloads/notes.txt")

POSITIVES (need to remain hot — labels populated):
  P1. Hostname + username + password in one line  (infrastructure + generic_credential)
  P2. Database connection strings with embedded creds  (infrastructure + generic_credential)
  P3. Concrete API key / bearer token disclosure  (auth_token / service_credential)
  P4. PEM block / ssh-rsa actually pasted  (key_material)
  P5. SSN / phone / email actually present  (pii)

Output: conversation_data.jsonl
"""
import json
import random
import string
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "conversation_data.jsonl"
RANDOM_SEED = 23
random.seed(RANDOM_SEED)

EXAMPLES: list[dict] = []


def add_neg(text: str) -> None:
    EXAMPLES.append({"text": text, "labels": []})


def add_pos(text: str, labels: list[str]) -> None:
    EXAMPLES.append({"text": text, "labels": labels})


# ── N1. Meta-discussion of classifier ────────────────────────────────────────
META_TEMPLATES = [
    "why does {label} fire on this prompt",
    "why did the model classify this as {label}",
    "this row classifies as {label} but it's clean",
    "see row {n} prompt fired from {client} - same prompt but labels as {label}",
    "the {label} rule fired on this prompt",
    "you flagged this as {label} but it isn't one",
    "ml says {label} {pct}% but there's nothing here",
    "{label} {pct}% above threshold for row {n}",
    "above threshold for {label}",
    "predicted {label} top score {pct}",
    "label this row as benign not {label}",
    "the classifier triggered {label} on row {n}",
    "row {n} ml_prediction shows {label} {pct} but no actual value",
    "this is a false positive for {label}",
    "{label} score {pct} on a prompt with no credential",
    "the dashboard shows {label} in red but the prompt is benign",
    "see prompt {n} - {label} {pct}%, infrastructure {pct2}%, what triggered it",
    "ml detection layer fired {label} on this conversation",
    "the rule engine returned clean but ml says {label}",
    "intent column shows {label} for row {n}",
    "above_threshold list contains {label} but content is empty",
    "ml_prediction.top_label = {label} for benign text",
    "false positive: {label} on dev chat about classification",
    "why is this scored {pct}% for {label}",
    "the model is confused between meta-discussion and actual {label}",
]
LABELS = ["pii", "infrastructure", "key_material", "auth_token",
          "service_credential", "generic_credential"]
CLIENTS = ["copilot cli", "claude code", "copilot vscode",
           "copilot in vscode", "claude-cli", "copilot-developer-cli"]


def gen_meta_discussions(n: int) -> None:
    for _ in range(n):
        tmpl = random.choice(META_TEMPLATES)
        text = tmpl.format(
            label=random.choice(LABELS),
            label2=random.choice(LABELS),
            pct=random.randint(60, 99),
            pct2=random.randint(60, 99),
            n=random.randint(100, 9999),
            client=random.choice(CLIENTS),
        )
        add_neg(text)


# ── N2. CLI tool mentions without credentials ───────────────────────────────
CLI_TOOL_TEMPLATES = [
    "let me try this with {tool}",
    "let me check with {tool}",
    "running the {tool} now",
    "ok let me run {tool}",
    "use {tool} to do this",
    "does {tool} support that flag",
    "{tool} keeps timing out on me",
    "see if {tool} has a config option for this",
    "compare output of {tool} vs the previous version",
    "i'll switch to {tool} for this test",
    "running with {tool} in the same shell",
    "{tool} doesn't seem to pick up my proxy env vars",
    "let me restart with {tool}",
    "trying the same thing with {tool}",
    "i'm using {tool} to debug",
    "spin up a sandbox with {tool}",
    "drop into a repl with {tool}",
    "{tool} version 2 fixed this for us",
    "the new {tool} build is in",
    "let me reproduce with {tool}",
]
CLI_TOOLS = [
    "copilot cli", "gh cli", "claude code", "claude cli",
    "the aws cli", "gcloud cli", "kubectl", "docker",
    "the new cli", "their cli", "the latest cli", "this cli tool",
    "the openai cli", "the github cli", "the anthropic cli",
]


def gen_cli_mentions(n: int) -> None:
    for _ in range(n):
        text = random.choice(CLI_TOOL_TEMPLATES).format(tool=random.choice(CLI_TOOLS))
        add_neg(text)


# ── N3. Dev chat using security-domain vocabulary (no actual values) ────────
DEV_CHAT_TEMPLATES = [
    "the auth_token rule keeps firing on benign requests",
    "we should rotate keys every 90 days per the policy",
    "validate input at all system boundaries",
    "never log passwords or credentials in plaintext",
    "use environment variables for storing api keys",
    "implement password complexity requirements per the spec",
    "the service_credential pattern is too broad",
    "dial in the threshold for generic_credential",
    "authentication tokens go in the header",
    "we use a secrets manager for production credentials",
    "the credential layer needs better signal",
    "credentials must be rotated quarterly",
    "deny list for known false positives",
    "the api key field accepts both bearer tokens and basic auth",
    "rate limit by api key not by ip",
    "we never store the password, only the hash",
    "the token expiry is 24 hours by default",
    "the proxy logs intercepted credentials separately",
    "secret detection runs on every commit",
    "leaked credentials must be rotated within 1 hour",
    "auth flow uses oauth with pkce",
    "session tokens are signed jwts",
    "the bearer token goes in the authorization header",
    "infrastructure secrets live in vault",
    "rotate all api keys before the audit",
    "this passed the credential scanner check",
    "the rule fired but there's no actual value to redact",
    "discussing rotation policy not actual keys",
    "talking about credentials in the abstract",
    "documentation about secret management",
]


def gen_dev_chat(n: int) -> None:
    for _ in range(n):
        text = random.choice(DEV_CHAT_TEMPLATES)
        if random.random() < 0.3:
            text = text + ". " + random.choice(DEV_CHAT_TEMPLATES)
        add_neg(text)


# ── N4. Short conversational acknowledgements ───────────────────────────────
SHORT_ACKS = [
    "started", "ok", "ok let me try", "ok just restarted",
    "looks good", "looks right", "yep", "thanks", "got it",
    "let me see", "one sec", "running it now",
    "rerunning", "rerun the build", "let me restart",
    "deploy the staging branch", "refactor this loop",
    "see the latest run", "check the logs", "what about row 4728",
    "see prompt 4728", "see 4729 too", "and 4729",
    "any updates", "still loading", "model is warming up",
    "the dashboard refreshed",
    "let me reproduce this", "let me check the db",
    "i restarted the proxy", "i restarted the classifier",
    "bumping the threshold helped", "lowered the threshold",
    "the column overlap is fixed", "the dashboard column header is wrong",
    "build green", "tests pass", "ci is green",
    "merging now", "let me push this branch",
    "rebased on main", "stash and pop",
]


def gen_short_acks(n: int) -> None:
    for _ in range(n):
        s = random.choice(SHORT_ACKS)
        add_neg(s)


# ── N5. File / location references — generic non-credential paths only ─────
# IMPORTANT: paths that point at credential/key/cert files are POSITIVES,
# not negatives — see KEY_FILE_REFS below. v5 had this wrong.
PATH_TEMPLATES = [
    "see the config at ~/.aws/config",
    "config lives in /etc/redasq/rules.json",
    "the env file is gitignored",
    "i use 1password for secrets",
    "see helm values for the secret refs",
    "/var/log/redasq/proxy.log has the request stream",
    "see the bashrc for env exports",
    "config map is in k8s, key name is API_KEY",
    "i moved the credentials.json to a safer location",
    "the readme documents where things live",
]


def gen_path_refs(n: int) -> None:
    for _ in range(n):
        text = random.choice(PATH_TEMPLATES)
        add_neg(text)


# ── P6. KEY/CERT FILE REFERENCES — POSITIVE for key_material ────────────────
# v6 fix: in v5 these were mislabeled as negatives. Per row 4722 in the
# debugging session, mentioning a path to a private key file IS the kind of
# disclosure intent we want flagged, even when the bytes themselves aren't
# pasted. The text "see my private key located at /path.pk" or "my certs are
# stored in downloads/v1.key" should fire key_material.
KEY_FILE_REFS = [
    "see my private key located at ~/Downloads/some.pk",
    "my certs are stored in downloads/{name}.key read it",
    "the cert is at /etc/ssl/certs/{name}.pem",
    "i keep my keys in ~/.ssh",
    "the deploy script reads /etc/secrets/{name}.key on startup",
    "the {name}-peer.crt was rotated as part of the cluster upgrade",
    "private key location is /etc/{name}/private.pem",
    "see ~/.netrc for the bearer token",
    "tokens are in keychain access",
    "the credentials file is at ~/.aws/credentials",
    "ssh into prod with -i ~/.ssh/{name}.pem",
    "ec2 keypair is at ~/Downloads/{name}.pem",
    "tls cert at /etc/letsencrypt/live/{name}/fullchain.pem",
    "kubeconfig with embedded cert is at ~/.kube/config",
    "private key file: /opt/secrets/{name}.key",
    "decrypt with the key in ~/.gnupg/secring.gpg",
    "load the cert from /var/lib/myapp/{name}.pem",
    "the api signing key sits at /etc/api/{name}.pem",
    "check /etc/ssh/ssh_host_rsa_key",
    "the master key is at /opt/keys/master.key",
]
KEY_FILE_NAMES = ["v1", "prod", "staging", "etcd", "myapp", "api", "deploy",
                  "k8s-master", "service", "client", "internal", "primary"]


def gen_key_file_refs(n: int) -> None:
    for _ in range(n):
        tmpl = random.choice(KEY_FILE_REFS)
        text = tmpl.format(name=random.choice(KEY_FILE_NAMES)) if "{name}" in tmpl else tmpl
        add_pos(text, ["key_material"])


# ── N6. Copilot CLI wrapper-text patterns (timestamp + tool boilerplate) ────
COPILOT_CLI_PREFIXES = [
    "2026-04-27T17:53:16.546Z",
    "2026-04-27T08:11:02.118Z",
    "2025-12-14T22:09:55.001Z",
    "2026-01-03T03:42:18.900Z",
]
COPILOT_CLI_SUFFIXES = [
    "No tables currently exist. Default tables (todos, todo_deps) will be created automatically when you first use the SQL tool.",
    "MCP server status: connected. Tools available: shell, read_file, sql.",
    "Current working directory: /Users/dev/projects/web-app. Git branch: main.",
    "Available tools: shell (run commands), read_file, write_file, sql (read-only).",
    "Session started. Type your question or 'exit' to quit.",
    "No errors found in the last 50 commands. Continue?",
]
COPILOT_CLI_INNOCUOUS_USER_TEXT = [
    "what files are in this directory",
    "summarize the recent commits",
    "show me the last 10 lines of the log",
    "rebase onto main",
    "format this go file",
    "search for the function handleRequest",
    "check the build status",
    "list the open pull requests",
    "describe the deployment process",
    "explain this regex",
]


def gen_copilot_cli_wrapped_innocuous(n: int) -> None:
    for _ in range(n):
        prefix = random.choice(COPILOT_CLI_PREFIXES)
        user_text = random.choice(COPILOT_CLI_INNOCUOUS_USER_TEXT)
        suffix = random.choice(COPILOT_CLI_SUFFIXES)
        text = f"{prefix} {user_text} {suffix}"
        add_neg(text)


# ── P1. Hostname + username + password in one line ──────────────────────────
HOSTNAME_TEMPLATES = [
    "my hostname is {host} and username is {user} and password is {pwd}",
    "server: {host}, user: {user}, pass: {pwd}",
    "ssh {user}@{host} password {pwd}",
    "host={host} user={user} password={pwd}",
    "connect to {host} with creds {user} / {pwd}",
    "the box is {host}, login is {user}, password is {pwd}",
    "use {user}:{pwd} to log into {host}",
    "{host} credentials: {user}/{pwd}",
    "production host {host} - admin {user} - pwd {pwd}",
    "test environment: host {host}, username {user}, password {pwd}",
]
HOSTS = [
    "xyz.com", "db.internal", "api.staging.corp", "10.0.5.12",
    "prod-redis-01.internal", "vault-shared.eng", "prod-api-1.aws",
    "192.168.0.1", "etcd-leader.cluster.local", "stage-mysql.svc",
    "auth-server.example.com", "build.ci.internal", "redis-replica.prod",
]
USERS = ["u1", "admin", "root", "deploy", "ops", "dba", "service",
         "appuser", "deploybot", "ci", "monitor", "backup"]
PASSWORDS = ["p1", "hunter2", "changeme", "letmein", "P@ssw0rd",
             "tempPass1", "rootroot", "admin123", "spring-2025",
             "prod-temp", "redacted-but-disclosed"]


def gen_hostname_creds(n: int) -> None:
    for _ in range(n):
        text = random.choice(HOSTNAME_TEMPLATES).format(
            host=random.choice(HOSTS),
            user=random.choice(USERS),
            pwd=random.choice(PASSWORDS),
        )
        add_pos(text, ["infrastructure", "generic_credential"])


# ── P2. DB connection strings with embedded credentials ─────────────────────
# v6 expansion: cover the prefix shapes that v5 missed in the legacy eval —
# MONGO_URI=mongodb+srv://, set X=… in env wrapper, export X=, DSN= variants.
DB_CONN_TEMPLATES = [
    "postgres://{user}:{pwd}@{host}/{db}",
    "mysql://{user}:{pwd}@{host}:3306/{db}",
    "mongodb://{user}:{pwd}@{host}/{db}",
    "mongodb+srv://{user}:{pwd}@{host}/{db}",
    "redis://default:{pwd}@{host}:6379/0",
    "DATABASE_URL=postgresql://{user}:{pwd}@{host}/{db}",
    "MONGO_URI=mongodb+srv://{user}:{pwd}@{host}/{db}",
    "REDIS_URL=redis://default:{pwd}@{host}:6379/0",
    "set DATABASE_URL=postgres://{user}:{pwd}@{host}/{db} in the env",
    "set REDIS_URL=redis://default:{pwd}@{host}:6379/0 in the env",
    "export DATABASE_URL=postgres://{user}:{pwd}@{host}/{db}",
    "export MONGO_URI=mongodb+srv://{user}:{pwd}@{host}/{db}",
    "DSN=postgres://{user}:{pwd}@{host}/{db}?sslmode=require",
    "DSN=mongodb+srv://{user}:{pwd}@{host}/{db}",
    "JDBC_URL=jdbc:postgresql://{user}:{pwd}@{host}/{db}",
]
DBS = ["app", "users", "orders", "ledger", "events", "main", "metrics", "billing", "analytics"]


def gen_db_conn(n: int) -> None:
    for _ in range(n):
        text = random.choice(DB_CONN_TEMPLATES).format(
            user=random.choice(USERS),
            pwd=random.choice(PASSWORDS) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
            host=random.choice(HOSTS),
            db=random.choice(DBS),
        )
        add_pos(text, ["infrastructure", "generic_credential"])


# ── P7. Host-only disclosures (no embedded credentials) ─────────────────────
# v6 fix: v5 only fires `infrastructure` reliably when paired with credentials.
# Plain conversational disclosures of a hostname slipped through (the
# "my db is hosted on jham.jham.com" case from the debugging session).
# These templates teach the model that a hostname mention alone is enough.
HOST_ONLY_TEMPLATES = [
    "my db is hosted on {h}",
    "my database is at {h}",
    "the prod api is on {h}",
    "we deploy to {h}",
    "{h} is our production database server",
    "ssh into {h} for debugging",
    "the postgres instance lives at {h}",
    "i'm connecting to {h} now",
    "monitor running on {h}",
    "primary db: {h}",
    "switching traffic to {h}",
    "redirect traffic from {h} to the new cluster",
    "the load balancer points at {h}",
    "internal kafka broker {h}",
    "elasticsearch is at {h}",
    "the new api gateway lives on {h}",
    "kubernetes master is {h}",
    "we proxy through {h}",
    "vault address: {h}",
    "the prod redis at {h} is failing over",
    "config server at {h}",
    "etcd leader is on {h}",
    "metrics endpoint: {h}",
    "ssh -i deploy.pem ec2-user@{h}",
]
# Diverse TLD shapes so the model doesn't overfit to .internal/.com/.corp.
EXTRA_HOSTS = [
    "jham.jham.com",
    "db-shared.org",
    "api.acme.dev",
    "backend.app.private",
    "primary.db.example.io",
    "v2.api.product.com",
    "prod-eu.east.cloud",
    "internal-svc.acme.io",
    "rds-prod.eu-west-1.amazonaws.internal",
    "kafka-prod-01.svc.cluster.local",
    "gateway.k8s.local",
    "auth.platform.dev",
    "monitor.observability.app",
    "redis-failover.eu.local",
    "cluster-prod.mongodb.net",
    "primary.mysql.local",
    "ingest.metrics.io",
    "billing-api.shared.svc",
]


def gen_host_only(n: int) -> None:
    pool = HOSTS + EXTRA_HOSTS
    for _ in range(n):
        text = random.choice(HOST_ONLY_TEMPLATES).format(h=random.choice(pool))
        add_pos(text, ["infrastructure"])


# ── P3. Bearer / API key concretely pasted ──────────────────────────────────
def gen_concrete_api_keys(n: int) -> None:
    for _ in range(n):
        choice = random.randint(0, 4)
        if choice == 0:
            tok = "sk-" + ''.join(random.choices(string.ascii_letters + string.digits, k=48))
            add_pos(f"my openai key: {tok}", ["service_credential"])
        elif choice == 1:
            tok = "ghp_" + ''.join(random.choices(string.ascii_letters + string.digits, k=36))
            add_pos(f"github pat: {tok}", ["service_credential"])
        elif choice == 2:
            tok = "Bearer " + ''.join(random.choices(string.ascii_letters + string.digits + "-_", k=120))
            add_pos(f"authorization: {tok}", ["auth_token"])
        elif choice == 3:
            tok = "AKIA" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
            add_pos(f"aws access key id: {tok}", ["service_credential"])
        else:
            tok = "xoxb-" + '-'.join(''.join(random.choices(string.digits, k=11)) for _ in range(2)) + '-' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
            add_pos(f"slack bot token: {tok}", ["service_credential"])


# ── P4. PEM blocks / ssh keys actually pasted ───────────────────────────────
PEM_BODIES = [
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ" + 'A' * 80,
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + 'B' * 100,
]


def gen_pem_blocks(n: int) -> None:
    for _ in range(n):
        body = random.choice(PEM_BODIES)
        # Truncated synthetic PEMs only — never include real key material in training data.
        text = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
        add_pos(text, ["key_material"])


def gen_ssh_keys(n: int) -> None:
    for _ in range(n):
        body = ''.join(random.choices(string.ascii_letters + string.digits + "+/", k=370))
        add_pos(f"ssh-rsa AAAA{body} user@host", ["key_material"])


# ── Build & write ───────────────────────────────────────────────────────────
def main():
    # Negatives — bias heavily toward the meta + CLI categories since those are
    # the FPs we keep hitting in real conversations.
    gen_meta_discussions(800)
    gen_cli_mentions(500)
    gen_dev_chat(400)
    gen_short_acks(300)
    gen_path_refs(300)
    gen_copilot_cli_wrapped_innocuous(400)

    # Positives — reinforce the patterns the model got right (4720) and
    # broaden the surface so contamination doesn't shift the prediction
    # (4728 was the same content but Copilot CLI's wrapper text moved the
    # output to pii — give the model more in-domain signal).
    gen_hostname_creds(400)
    gen_db_conn(400)              # v6: extra prefix variants (MONGO_URI, set X=…)
    gen_host_only(400)            # v6: host-only disclosures w/ diverse TLDs
    gen_key_file_refs(300)        # v6: relabel of v5 mistakes (path refs to keys)
    gen_concrete_api_keys(300)
    gen_pem_blocks(150)
    gen_ssh_keys(150)

    random.shuffle(EXAMPLES)
    with OUTPUT_PATH.open("w") as f:
        for ex in EXAMPLES:
            f.write(json.dumps(ex) + "\n")

    neg = sum(1 for e in EXAMPLES if not e["labels"])
    print(f"Wrote {len(EXAMPLES)} examples to {OUTPUT_PATH}")
    print(f"  negatives (FP suppression): {neg}")
    print(f"  positives:                  {len(EXAMPLES) - neg}")
    from collections import Counter
    c = Counter()
    for e in EXAMPLES:
        for l in e["labels"]:
            c[l] += 1
    for l, n in c.most_common():
        print(f"    {l:25s} {n}")


if __name__ == "__main__":
    main()
