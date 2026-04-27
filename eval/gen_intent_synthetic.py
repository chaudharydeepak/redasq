"""
Generate synthetic positive + negative examples for intent classification.

For each intent label, produce 500-1000 positive examples in varied contexts
(structured, conversational, embedded in prose). For negatives, produce
adversarial cases that LOOK suspicious but contain no real entities.

Output: synthetic_intent_data.jsonl, combined with prepare_intent_data.py
output via combine_intent_data.py.
"""
import json
import random
import string
from pathlib import Path

import exrex

OUTPUT_PATH = Path(__file__).parent / "synthetic_intent_data.jsonl"
RANDOM_SEED = 13
POSITIVES_PER_INTENT = 800
NEGATIVES_TOTAL = 3000
random.seed(RANDOM_SEED)


# ── Value generators ──────────────────────────────────────────────────────────
def gen_password():
    bases = ["P@ss", "Sup3r", "Adm1n", "Welc0me", "Spr1ng", "Summ3r", "Vault",
             "Master", "Backup", "Secret", "Deploy", "Cluster", "Worker",
             "Bastion", "Failover", "Rotation"]
    suffixes = ["!", "@2024", "#321", "$$$", "%99", "!42", "_2026", "@deploy",
                "@prod", "!secure", "#admin", "$3cret", "_temp", "!new"]
    return (random.choice(bases) + random.choice(string.ascii_letters)
            + "".join(random.choices(string.digits, k=random.randint(2, 4)))
            + random.choice(suffixes))


def gen_aws_key():
    return exrex.getone(r"AKIA[A-Z0-9]{16}")


def gen_github_token():
    return exrex.getone(r"ghp_[A-Za-z0-9]{36}")


def gen_anthropic_key():
    return exrex.getone(r"sk-ant-api03-[A-Za-z0-9_-]{40}")


def gen_openai_key():
    return exrex.getone(r"sk-(?:proj-)?[A-Za-z0-9_-]{40}")


def gen_stripe_key():
    return exrex.getone(r"sk_(?:live|test)_[A-Za-z0-9]{24}")


def gen_jwt():
    return exrex.getone(r"eyJ[A-Za-z0-9_-]{20,40}\.eyJ[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{20,40}")


def gen_email():
    firsts = ["alice", "bob", "carol", "dave", "eve", "frank", "grace",
              "harry", "iris", "jack", "kate", "liam", "mia", "noah", "olivia",
              "peter", "quinn", "rachel", "sam", "tina"]
    lasts = ["smith", "jones", "brown", "davis", "wilson", "garcia", "patel",
             "kim", "chen", "khan", "lee", "ali", "shah", "wong", "perez",
             "anderson", "martinez", "rodriguez", "miller", "taylor"]
    domains = ["gmail.com", "example.com", "company.io", "acme.co.uk",
               "startup.dev", "internal.corp", "firm.org", "outlook.com",
               "yahoo.com", "protonmail.com", "fastmail.com", "icloud.com",
               "globalcorp.net", "techcorp.dev"]
    sep = random.choice([".", "_", "+", ""])
    f, l, d = random.choice(firsts), random.choice(lasts), random.choice(domains)
    if random.random() < 0.3:
        return f"{f}{sep}{l}{random.randint(1, 999)}@{d}"
    return f"{f}{sep}{l}@{d}"


def gen_ssn():
    return exrex.getone(r"\d{3}-\d{2}-\d{4}")


def gen_credit_card():
    prefixes = ["4", "51", "52", "53", "54", "55", "34", "37", "6011"]
    prefix = random.choice(prefixes)
    length = 16 if not prefix.startswith("3") else 15
    body = prefix + "".join(random.choices(string.digits, k=length - len(prefix) - 1))
    s = 0
    for i, d in enumerate(reversed(body)):
        d = int(d)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    check = (10 - s % 10) % 10
    return body + str(check)


def gen_internal_ip():
    return exrex.getone(r"(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def gen_internal_hostname():
    services = ["rds", "redis", "kafka", "mongo", "postgres", "mysql", "vault",
                "consul", "etcd", "grafana", "prometheus", "elastic", "kibana",
                "api", "auth", "billing", "checkout", "payment", "worker",
                "queue", "cache", "search", "ingest", "egress", "gateway",
                "audit", "metrics", "logging", "scheduler", "notifier"]
    envs = ["prod", "staging", "dev", "qa", "test", "uat", "sandbox", "internal",
            "eu-prod", "us-west", "canary", "blue", "green"]
    suffixes = [".internal", ".local", ".corp", ".internal.aws",
                ".svc.cluster.local", ".internal.gcp", ".acme.local",
                ".company.internal", ".infra.local"]
    s, e = random.choice(services), random.choice(envs)
    if random.random() < 0.5:
        return f"{s}-{e}{random.choice(suffixes)}"
    return f"{s}{random.randint(1, 9)}{random.choice(suffixes)}"


def gen_db_connection():
    schemes = ["postgresql", "postgres", "mysql", "mongodb+srv", "mongodb",
               "redis", "amqp", "mariadb"]
    users = ["admin", "root", "app_user", "deploy", "service", "rds_user", "ops"]
    pwds = ["s3cret", "P@ssw0rd", "rootpw", "Adm1n@2024", "DeployKey99"]
    hosts = [gen_internal_hostname() for _ in range(20)] + [
        "10.0.1.5", "10.2.3.4", "192.168.1.10", "localhost", "db.acme.com"
    ]
    dbs = ["users", "production", "staging", "myapp", "payments", "analytics"]
    ports = [3306, 5432, 6379, 27017, 5672]
    scheme = random.choice(schemes)
    user, pwd = random.choice(users), random.choice(pwds)
    host = random.choice(hosts)
    db = random.choice(dbs)
    if random.random() < 0.6:
        return f"{scheme}://{user}:{pwd}@{host}:{random.choice(ports)}/{db}"
    return f"{scheme}://{user}:{pwd}@{host}/{db}"


def gen_private_key_file():
    return random.choice([
        "key.pem", "id_rsa", "id_ed25519", "id_ecdsa", "deploy.pem",
        "~/.ssh/id_rsa", "~/.ssh/prod.pem", "/etc/ssl/private/server.key",
        "prod-deploy.ppk", "ca.p12", "client-cert.pfx", "staging.pem",
        "ci-deploy.pem", "/keys/master.pem", "rsa_4096.pem",
    ])


def gen_ssh_command():
    users = ["ec2-user", "ubuntu", "admin", "deploy", "root", "centos"]
    keys = [gen_private_key_file() for _ in range(10)]
    hosts = [gen_internal_hostname() for _ in range(15)] + [
        "10.2.3.4", "10.0.1.5", "192.168.5.10"
    ]
    cmds = ["ssh", "scp", "rsync"]
    cmd = random.choice(cmds)
    u, h, k = random.choice(users), random.choice(hosts), random.choice(keys)
    if cmd == "ssh":
        if random.random() < 0.6:
            return f"ssh -i {k} {u}@{h}"
        return f"ssh {u}@{h}"
    if cmd == "scp":
        return f"scp -i {k} build.tar.gz {u}@{h}:/opt/"
    return f"rsync -avz -e 'ssh -i {k}' ./dist/ {u}@{h}:/srv/"


# ── Templates per intent ──────────────────────────────────────────────────────
# Each template has {value} placeholder. The text gets the listed labels.

TEMPLATES = {
    # ── PII ───────────────────────────────────────────────────────────────────
    "pii": [
        # SSN
        ("the social security number is {value}", gen_ssn),
        ("patient ssn: {value}", gen_ssn),
        ("his ssn on file is {value}", gen_ssn),
        ("ssn: {value}", gen_ssn),
        ("verify ssn {value} for the loan application", gen_ssn),
        ("background check ssn = {value}", gen_ssn),
        # Credit card
        ("card number {value}", gen_credit_card),
        ("the customer's card is {value}", gen_credit_card),
        ("charge to {value}", gen_credit_card),
        ("cc on file: {value}", gen_credit_card),
        ("payment method {value} declined", gen_credit_card),
        # Email
        ("email me at {value}", gen_email),
        ("contact: {value}", gen_email),
        ("loop in {value} on this thread", gen_email),
        ("from {value}", gen_email),
        ("the customer reported the issue from {value}", gen_email),
        ("send the report to {value}", gen_email),
        ("@{value} please review", gen_email),
        ("billing email {value}", gen_email),
    ],
    # ── Infrastructure ────────────────────────────────────────────────────────
    "infrastructure": [
        # Internal IP
        ("the server is at {value}", gen_internal_ip),
        ("ssh user@{value}", gen_internal_ip),
        ("ping {value} to test connectivity", gen_internal_ip),
        ("internal host {value}", gen_internal_ip),
        ("the bastion ip is {value}", gen_internal_ip),
        ("vpc cidr includes {value}", gen_internal_ip),
        ("k8s pod ip {value}", gen_internal_ip),
        ("connect to {value} on port 22", gen_internal_ip),
        # Internal hostname
        ("the host is {value}", gen_internal_hostname),
        ("deploy to {value}", gen_internal_hostname),
        ("DATABASE_HOST={value}", gen_internal_hostname),
        ("connect to {value}", gen_internal_hostname),
        ("internal hostname {value}", gen_internal_hostname),
        ("REDIS_HOST={value}", gen_internal_hostname),
        ("the prod server is {value}", gen_internal_hostname),
        ("service endpoint {value}", gen_internal_hostname),
        ("alert: high cpu on {value}", gen_internal_hostname),
        ("postgres failover from {value}", gen_internal_hostname),
        # DB connection string
        ("DATABASE_URL={value}", gen_db_connection),
        ("connect to {value}", gen_db_connection),
        ("the connection string is {value}", gen_db_connection),
        ("DB_URL={value}", gen_db_connection),
        ("MONGO_URI={value}", gen_db_connection),
        ("REDIS_URL={value}", gen_db_connection),
    ],
    # ── Key material ──────────────────────────────────────────────────────────
    "key_material": [
        ("the key file is {value}", gen_private_key_file),
        ("private key path: {value}", gen_private_key_file),
        ("load {value} for authentication", gen_private_key_file),
        ("ssh-add {value}", gen_private_key_file),
        ("use key {value}", gen_private_key_file),
        ("key location: {value}", gen_private_key_file),
        ("-i {value}", gen_private_key_file),
        ("ssh_key: {value}", gen_private_key_file),
        ("our deploy key is {value}", gen_private_key_file),
        ("found {value} on the laptop, rotating", gen_private_key_file),
    ],
    # ── Auth token (JWT, basic, bearer) ───────────────────────────────────────
    "auth_token": [
        ("Authorization: Bearer {value}", gen_jwt),
        ("JWT={value}", gen_jwt),
        ("token: {value}", gen_jwt),
        ("x-auth-token: {value}", gen_jwt),
        ("ACCESS_TOKEN={value}", gen_jwt),
        ("session token {value}", gen_jwt),
        ("id_token: {value}", gen_jwt),
        ("bearer {value}", gen_jwt),
        ("Cookie: jwt={value}", gen_jwt),
        ("the jwt for the session is {value}", gen_jwt),
        ("decoded jwt: {value}", gen_jwt),
        ("refresh token endpoint returned {value}", gen_jwt),
    ],
    # ── Service credentials (AWS, GitHub, Anthropic, OpenAI, Stripe) ─────────
    "service_credential": [
        ("my AWS access key is {value}", gen_aws_key),
        ("AWS_ACCESS_KEY_ID={value}", gen_aws_key),
        ("aws_access_key_id = {value}", gen_aws_key),
        ("use {value} for s3 access", gen_aws_key),
        ("[default]\\naws_access_key_id = {value}", gen_aws_key),
        ("GitHub token: {value}", gen_github_token),
        ("GH_TOKEN={value}", gen_github_token),
        ("auth with PAT {value}", gen_github_token),
        ("Authorization: token {value}", gen_github_token),
        ("ANTHROPIC_API_KEY={value}", gen_anthropic_key),
        ("my anthropic key is {value}", gen_anthropic_key),
        ("use claude with key {value}", gen_anthropic_key),
        ("OPENAI_API_KEY={value}", gen_openai_key),
        ("my openai key: {value}", gen_openai_key),
        ("for chatgpt use {value}", gen_openai_key),
        ("STRIPE_SECRET_KEY={value}", gen_stripe_key),
        ("stripe key {value}", gen_stripe_key),
        ("billing service authenticated with {value}", gen_stripe_key),
    ],
    # ── Generic credentials (passwords, generic API keys, secrets) ────────────
    "generic_credential": [
        # Conversational password
        ("my password is {value}", gen_password),
        ("the password is {value}", gen_password),
        ("password for the database is {value}", gen_password),
        ("use {value} as the password", gen_password),
        ("login with password {value}", gen_password),
        ("set the new password to {value}", gen_password),
        ("temp password is {value}, change after first login", gen_password),
        ("rotated to {value} this morning", gen_password),
        ("admin/{value} for the staging account", gen_password),
        ("password={value}", gen_password),
        ("PASSWORD: {value}", gen_password),
        ("DB_PASSWORD={value}", gen_password),
        ('password="{value}"', gen_password),
        # Generic API key / secret
        ("api_key={value}", lambda: "".join(random.choices(string.ascii_letters + string.digits, k=32))),
        ("API_KEY: {value}", lambda: "".join(random.choices(string.ascii_letters + string.digits, k=32))),
        ("SECRET_KEY={value}", lambda: "".join(random.choices(string.ascii_letters + string.digits, k=32))),
        ("secret: {value}", lambda: "".join(random.choices(string.ascii_letters + string.digits, k=24))),
        ("the api key is {value}", lambda: "".join(random.choices(string.ascii_letters + string.digits, k=32))),
    ],
}


# ── Negative templates (look secret-y but aren't) ─────────────────────────────
NEGATIVE_TEMPLATES = [
    # Code identifiers
    "func {ident}(body []byte) string {{ return body }}",
    "var {ident} = {ident}(req.URL.Path)",
    "import {{ {ident} }} from '@/lib/{ident}'",
    "{ident} := make([]byte, 0)",
    "// {ident} handles the {ident} request",
    "Called the Read tool with input: {{\"file_path\":\"/Users/dev/{ident}.go\"}}",
    "// Function: {ident}, Returns: bool",
    "if {ident} == nil {{ return errors.New(\"empty\") }}",
    # Git output
    "[master {hash}] fix: {ident} update",
    "remote: To https://github.com/user/repo.git\\n   {hash}..{hash} master -> master",
    "commit {longhash}\\nAuthor: dev\\nDate: today",
    "Fast-forward {hash}..{hash}",
    # Timestamps in logs
    "{ts} INFO server started on port {port}",
    "{ts} REQUEST: POST /v1/messages body=12345 bytes",
    "{ts} HEADER {header}: value-here",
    "{ts} {ident} called with {ident} parameter",
    # Versions and arch
    "Build version {version} for {arch}",
    "Running on Node.js {version}",
    "Updated {ident} to {version}",
    "Detected platform: {arch}",
    # HTTP headers
    "request headers: {header}, {header}, {header}",
    "for _, h := range []string{{\"{header}\", \"{header}\"}}",
    "{header}: {ident}",
    # URLs without creds
    "Fetched https://github.com/{ident}/{ident} successfully",
    "see https://docs.example.com/{ident}/{ident} for details",
    "GET /api/v1/{ident}/{ident}",
    # UUIDs (session/machine ids, NOT credentials)
    "session_id: {uuid}",
    "machine id is {uuid}",
    "X-Client-Machine-Id: {uuid}",
    "request_id={uuid}",
    "device_id: {uuid}",
    # Dev conversation
    "i need to debug the {ident} thing",
    "what is the difference between {ident} and {ident}",
    "the build of {ident} is failing",
    "lets refactor {ident} module",
    "running on macos with python {version}",
    "the gpu instance is running {version}",
    # Discussion of secrets without containing them
    "we should rotate {ident} regularly",
    "implement password complexity requirements",
    "use bcrypt for password hashing",
    "the password reset flow needs testing",
    "PCI DSS scope includes credit card data handling",
    "internal IPs should not be in public DNS",
    "ssh keepalive is configured at 60 seconds",
    "github tokens expire after 90 days",
    # Build outputs
    "==> Updating Homebrew...",
    "Successfully built {hash}",
    "Step 1/8 : FROM golang:1.22",
    "1 file changed, 1 insertion(+), 1 deletion(-)",
]


def fill_negative_template(template: str) -> str:
    return template.format(
        hash="".join(random.choices("0123456789abcdef", k=7)),
        longhash="".join(random.choices("0123456789abcdef", k=40)),
        ts=f"2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}T"
           f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(0,999):03d}Z",
        port=random.choice(["3000", "8080", "8443", "5432", "6379", "9090", "7778"]),
        version=f"v{random.randint(0,24)}.{random.randint(0,30)}.{random.randint(0,99)}",
        arch=random.choice(["x64", "x86_64", "arm64", "aarch64", "amd64"]),
        ident=random.choice([
            "extractTelemetryInfo", "tlsClient", "ExtractPrompts", "ExtractUserQuery",
            "debugf", "stripPort", "isTelemetry", "ParseRequest", "InspectAndStore",
            "writeBlockedResponse", "RedactBodyForForwarding", "SavePrompt",
            "user_id", "session_id", "device_id", "client_id", "request_id",
            "todos", "todo_deps", "users_v2", "events_log", "audit_trail",
            "redasq", "promptguard", "claude", "copilot", "anthropic",
        ]),
        header=random.choice([
            "X-Session-Id", "X-Vscode-Session-Id", "Vscode-Sessionid",
            "X-Client-Session-Id", "X-Github-Session-Id", "Copilot-Integration-Id",
            "X-Request-Id", "User-Agent", "Content-Type", "Accept",
            "Authorization", "X-Forwarded-For", "X-Real-IP",
        ]),
        uuid=f"{''.join(random.choices('0123456789abcdef', k=8))}-"
             f"{''.join(random.choices('0123456789abcdef', k=4))}-"
             f"{''.join(random.choices('0123456789abcdef', k=4))}-"
             f"{''.join(random.choices('0123456789abcdef', k=4))}-"
             f"{''.join(random.choices('0123456789abcdef', k=12))}",
    )


# Realistic surrounding noise.
NOISE_PRE = ["", "FYI ", "Hi team, ", "Quick note: ", "Heads up — ",
             "Following up: ", "From the deploy logs: ",
             "While debugging, I noticed ", "In the staging env, "]
NOISE_POST = ["", " — let me know if that works.", " (please rotate ASAP).",
              ". Updating the doc now.", "; do not share this externally.",
              " — this expires next week.", ". Filed under #infra."]


def add_noise(text: str) -> str:
    return random.choice(NOISE_PRE) + text + random.choice(NOISE_POST)


def main() -> None:
    examples: list[dict] = []

    # 1. Positive examples per intent.
    for intent, templates in TEMPLATES.items():
        for _ in range(POSITIVES_PER_INTENT):
            template, gen_fn = random.choice(templates)
            value = gen_fn()
            text = template.format(value=value)
            if random.random() < 0.5:
                text = add_noise(text)
            examples.append({"text": text, "labels": [intent]})

    # 2. Multi-intent positives (mix two entities in one prompt).
    pairs = [
        ("infrastructure", "generic_credential"),
        ("infrastructure", "service_credential"),
        ("key_material", "infrastructure"),
        ("pii", "generic_credential"),
        ("auth_token", "infrastructure"),
    ]
    for _ in range(500):
        i1, i2 = random.choice(pairs)
        t1, fn1 = random.choice(TEMPLATES[i1])
        t2, fn2 = random.choice(TEMPLATES[i2])
        v1, v2 = fn1(), fn2()
        text = f"{t1.format(value=v1)} and {t2.format(value=v2)}"
        examples.append({"text": text, "labels": sorted({i1, i2})})

    # 3. Negative examples (look-alike but no entities).
    for _ in range(NEGATIVES_TOTAL):
        template = random.choice(NEGATIVE_TEMPLATES)
        text = fill_negative_template(template)
        if random.random() < 0.4:
            text = add_noise(text)
        examples.append({"text": text, "labels": []})

    random.shuffle(examples)
    with OUTPUT_PATH.open("w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"Wrote {len(examples)} synthetic examples → {OUTPUT_PATH}")
    from collections import Counter
    label_counter = Counter()
    for ex in examples:
        for l in ex["labels"]:
            label_counter[l] += 1
        if not ex["labels"]:
            label_counter["__none__"] += 1
    print("\nLabel frequency:")
    for label, n in label_counter.most_common():
        print(f"  {label:25s} {n:5d}")


if __name__ == "__main__":
    main()
