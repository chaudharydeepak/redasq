"""
Generate synthetic labeled training data for fine-tuning GLiNER.

Targets ~1000-2000 examples per entity type with high variation:
  - Many unique values (regex-generated + hand-curated)
  - Many context templates (structured / conversational / embedded in prose)
  - Mix of leading/trailing realistic surrounding text
  - Negative examples (keyword without a real value)
  - Multi-entity examples (a single text containing multiple entity types)

Output: training_data.json (GLiNER format).
"""
import json
import random
import string
from dataclasses import dataclass, field
from pathlib import Path

import exrex

OUTPUT_PATH = Path(__file__).parent / "training_data.json"
RANDOM_SEED = 42
TARGET_PER_ENTITY = 1500
MULTI_ENTITY_EXAMPLES = 1000

random.seed(RANDOM_SEED)

# ── Realistic noise — words/phrases used to embed entities in larger context ──
NOISE_PRE = [
    "", "FYI ", "Hi team, ", "Quick note: ", "Heads up — ",
    "Following up: ", "From the deploy logs: ", "After rotation, ",
    "Reminder, ", "Documenting: ", "For the runbook: ", "Just a note, ",
    "@here ", "FYI for ops, ", "Per yesterday's incident, ",
    "While debugging, I noticed ", "In the staging env, ",
]
NOISE_POST = [
    "", " — let me know if that works.", " (please rotate ASAP).",
    " — copying for the record.", ". Thanks!", ". Updating the doc now.",
    "; do not share this externally.", " — this expires next week.",
    ". Confirmed working in prod.", ". Filed under #infra.",
    ". Will rotate after deploy.", ". Documenting in the wiki.",
    " — let's discuss in standup.", ". Adding to vault tomorrow.",
]


def add_noise(text: str) -> str:
    """Wrap text with realistic surrounding context."""
    return random.choice(NOISE_PRE) + text + random.choice(NOISE_POST)


# ── Value generators ──────────────────────────────────────────────────────────
def realistic_passwords(n: int) -> list[str]:
    bases = [
        "P@ss", "Sup3r", "Adm1n", "Welc0me", "Spr1ng", "Summ3r", "Prod",
        "Stag", "K8s", "Docker", "Redis", "Postgres", "MySQL", "Mongo",
        "Vault", "Consul", "Backup", "Deploy", "Master", "Hunter",
    ]
    suffixes = [
        "!", "@2024", "#321", "$$$", "%99", "!42", "&amp;3", "*99",
        "_2026", "@deploy", "@prod", "!secure", "#admin", "$3cret",
    ]
    out = set()
    while len(out) < n:
        body = random.choice(bases) + random.choice(string.ascii_letters)
        body += "".join(random.choices(string.digits, k=random.randint(2, 4)))
        body += random.choice(suffixes)
        out.add(body)
    return list(out)


def realistic_emails(n: int) -> list[str]:
    firsts = ["alice", "bob", "carol", "dave", "eve", "frank", "grace",
              "harry", "iris", "jack", "kate", "liam", "mia", "noah", "olivia"]
    lasts = ["smith", "jones", "brown", "davis", "wilson", "garcia", "patel",
             "kim", "chen", "khan", "lee", "ali", "shah", "wong", "perez"]
    domains = ["gmail.com", "example.com", "company.io", "acme.co.uk",
               "startup.dev", "internal.corp", "firm.org", "outlook.com",
               "yahoo.com", "protonmail.com", "fastmail.com", "icloud.com"]
    out = set()
    while len(out) < n:
        f, l, d = random.choice(firsts), random.choice(lasts), random.choice(domains)
        sep = random.choice([".", "_", "+", ""])
        if random.random() < 0.3:
            email = f"{f}{sep}{l}{random.randint(1, 999)}@{d}"
        else:
            email = f"{f}{sep}{l}@{d}"
        out.add(email)
    return list(out)


def realistic_hostnames(n: int) -> list[str]:
    services = ["rds", "redis", "kafka", "mongo", "postgres", "mysql", "vault",
                "consul", "etcd", "grafana", "prometheus", "elastic", "kibana",
                "api", "auth", "billing", "checkout", "payment", "worker",
                "queue", "cache", "search", "ingest", "egress", "gateway"]
    envs = ["prod", "staging", "dev", "qa", "test", "uat", "sandbox", "internal"]
    suffixes = [".internal", ".local", ".corp", ".internal.aws",
                ".svc.cluster.local", ".internal.gcp", ".acme.local",
                ".company.internal", ".infra.local"]
    out = set()
    while len(out) < n:
        s, e = random.choice(services), random.choice(envs)
        if random.random() < 0.5:
            host = f"{s}-{e}{random.choice(suffixes)}"
        else:
            host = f"{s}{random.randint(1, 9)}{random.choice(suffixes)}"
        out.add(host)
    return list(out)


def realistic_db_strings(n: int) -> list[str]:
    schemes = ["postgresql", "postgres", "mysql", "mongodb+srv", "mongodb",
               "redis", "amqp", "mariadb"]
    users = ["admin", "root", "app_user", "deploy", "service", "rds_user", "ops"]
    pwds = ["s3cret", "P@ssw0rd", "rootpw", "Adm1n@2024", "DeployKey99",
            "Pg%40ssw0rd", "h3xpw", "pwd!2024", "LongerSecret_42"]
    hosts = realistic_hostnames(20) + ["10.0.1.5", "10.2.3.4", "192.168.1.10",
                                        "localhost", "db.acme.com"]
    dbs = ["users", "production", "staging", "myapp", "payments", "analytics",
           "events", "logs", "billing", "auth"]
    ports = [3306, 5432, 6379, 27017, 5672]
    out = set()
    while len(out) < n:
        scheme = random.choice(schemes)
        user, pwd = random.choice(users), random.choice(pwds)
        host = random.choice(hosts)
        db = random.choice(dbs)
        if random.random() < 0.6:
            port = random.choice(ports)
            out.add(f"{scheme}://{user}:{pwd}@{host}:{port}/{db}")
        else:
            out.add(f"{scheme}://{user}:{pwd}@{host}/{db}")
    return list(out)


def realistic_ssh_commands(n: int) -> list[str]:
    users = ["ec2-user", "ubuntu", "admin", "deploy", "root", "centos",
             "fedora", "core", "ops", "sre"]
    keys = ["key.pem", "id_rsa", "id_ed25519", "deploy.pem",
            "~/.ssh/prod.pem", "/keys/staging.key", "ci-deploy.pem"]
    hosts = realistic_hostnames(15) + ["10.2.3.4", "10.0.1.5", "192.168.5.10"]
    ports = ["", " -p 22", " -p 2222", " -p 22000"]
    cmds = ["ssh", "scp", "rsync"]
    out = set()
    while len(out) < n:
        cmd = random.choice(cmds)
        u, h, k, p = (random.choice(users), random.choice(hosts),
                      random.choice(keys), random.choice(ports))
        use_key = random.random() < 0.6
        if cmd == "ssh":
            if use_key:
                out.add(f"ssh -i {k}{p} {u}@{h}")
            else:
                out.add(f"ssh{p} {u}@{h}")
        elif cmd == "scp":
            out.add(f"scp -i {k} build.tar.gz {u}@{h}:/opt/")
        else:
            out.add(f"rsync -avz -e 'ssh -i {k}' ./dist/ {u}@{h}:/srv/")
    return list(out)


def credit_cards(n: int) -> list[str]:
    """Generate Luhn-valid credit card numbers."""
    prefixes = ["4", "51", "52", "53", "54", "55", "34", "37", "6011"]
    out = set()
    while len(out) < n:
        prefix = random.choice(prefixes)
        length = 16 if not prefix.startswith("3") else 15
        body = prefix + "".join(random.choices(string.digits, k=length - len(prefix) - 1))
        # Luhn check digit
        s = 0
        for i, d in enumerate(reversed(body)):
            d = int(d)
            if i % 2 == 0:
                d *= 2
                if d > 9:
                    d -= 9
            s += d
        check = (10 - s % 10) % 10
        out.add(body + str(check))
    return list(out)


# ── Entity definitions with rich templates ────────────────────────────────────
@dataclass
class EntitySpec:
    label: str
    regex: str | None = None
    values_fn: callable = None  # called with (n) → list[str]
    values: list[str] = field(default_factory=list)
    templates: list[str] = field(default_factory=list)
    negative_templates: list[str] = field(default_factory=list)


PASSWORD_TEMPLATES = [
    # Conversational
    "my password is {value}",
    "the password is {value}",
    "the password for the database is {value}",
    "password should be {value}",
    "use {value} as the password",
    "I set the new password to {value}",
    "the temp password is {value}, change it after login",
    "use {value} for now",
    "log in with password {value}",
    "username admin password {value}",
    "the credentials are user=admin pass={value}",
    "rotated to {value} this morning",
    "new password: {value}",
    "passcode {value}",
    "secret is {value}",
    "current password: {value}",
    "set DB_PASSWORD to {value}",
    "the postgres password is {value}",
    "my admin password is {value}",
    "generated password {value} for the new account",
    # Structured
    "password={value}",
    "PASSWORD: {value}",
    "DB_PASSWORD={value}",
    'password="{value}"',
    "password='{value}'",
    "passwd: {value}",
    "PWD={value}",
    "DATABASE_PASSWORD={value}",
    "REDIS_PASSWORD={value}",
    "MYSQL_ROOT_PASSWORD={value}",
    "VAULT_PASSWORD={value}",
    "auth: {{ password: '{value}' }}",
]

PASSWORD_NEGATIVES = [
    "what is a password manager",
    "you should rotate your password regularly",
    "the password requirements are 8 characters minimum",
    "use bcrypt for password hashing",
    "the password field is required",
    "send a password reset email",
    "two-factor auth is more secure than passwords alone",
    "we never log passwords in plaintext",
    "implement password rotation policy",
    "passwords are stored hashed with argon2",
    "the password input field has a show/hide toggle",
    "password manager integration",
    "test the password reset flow",
    "passwords must be at least 12 characters",
    "I forgot my password — using the reset link",
]

EMAIL_TEMPLATES = [
    "email me at {value}",
    "send the report to {value}",
    "contact: {value}",
    "user email is {value}",
    "from: {value}",
    "{value} got the invite",
    "loop in {value} on this thread",
    "{value} sent the document",
    "cc {value} on the response",
    "the customer's email is {value}",
    "reach out to {value}",
    "@{value}",
    "email: {value}",
    "primary contact {value}",
    "billing email {value}",
    "owner: {value}",
    "registered to {value}",
]

EMAIL_NEGATIVES = [
    "what is the email address format",
    "validate email field on the form",
    "send email notifications to admins",
    "the email service is down",
    "implement email confirmation flow",
    "email templates need updating",
]


ENTITIES: list[EntitySpec] = [
    EntitySpec(
        label="aws_access_key",
        regex=r"AKIA[A-Z0-9]{16}",
        templates=[
            "my AWS access key is {value}",
            "AWS_ACCESS_KEY_ID={value}",
            "use {value} to authenticate to S3",
            "Set the access key to {value}",
            "AWS access key id: {value}",
            "credentials: {value}",
            "export AWS_ACCESS_KEY_ID={value}",
            "the rotated key is {value}, please update",
            "aws creds {value}",
            "my aws key {value}",
            "for the s3 bucket use {value}",
            "key={value}",
            "old aws key {value}, new one coming",
            "AWS_ACCESS_KEY={value}",
            "[default] aws_access_key_id = {value}",
        ],
    ),
    EntitySpec(
        label="github_token",
        regex=r"ghp_[A-Za-z0-9]{36}",
        templates=[
            "GitHub token: {value}",
            "GITHUB_TOKEN={value}",
            "auth with {value}",
            "use this PAT: {value}",
            "the github personal access token is {value}",
            "my gh token {value}",
            "GH_TOKEN={value}",
            "Authorization: token {value}",
            "github auth {value}",
            "gh auth login --with-token {value}",
            "the deploy token is {value}",
            "personal access token: {value}",
            "ci/cd token {value}",
            "github creds: {value}",
            "x-github-token: {value}",
        ],
    ),
    EntitySpec(
        label="anthropic_key",
        regex=r"sk-ant-api03-[A-Za-z0-9_-]{40}",
        templates=[
            "ANTHROPIC_API_KEY={value}",
            "my anthropic key is {value}",
            "use api key {value} for claude",
            "rotated to {value}",
            "claude key: {value}",
            "anthropic creds {value}",
            "the api key is {value}",
            "x-api-key: {value}",
            "ANTHROPIC_KEY={value}",
            "set claude api key to {value}",
            "anthropic_api_key = {value}",
            "for claude use {value}",
        ],
    ),
    EntitySpec(
        label="openai_key",
        regex=r"sk-(?:proj-)?[A-Za-z0-9_-]{40}",
        templates=[
            "OPENAI_API_KEY={value}",
            "use {value} for openai",
            "my openai key: {value}",
            "openai creds: {value}",
            "the gpt key is {value}",
            "Authorization: Bearer {value}",
            "openai api key {value}",
            "set OPENAI_KEY={value}",
            "for chatgpt use {value}",
            "openai_api_key = {value}",
            "x-openai-key: {value}",
        ],
    ),
    EntitySpec(
        label="stripe_key",
        regex=r"sk_(?:live|test)_[A-Za-z0-9]{24}",
        templates=[
            "STRIPE_SECRET_KEY={value}",
            "use stripe key {value}",
            "pass {value} to stripe client",
            "stripe creds {value}",
            "the stripe secret is {value}",
            "stripe.apiKey = '{value}'",
            "billing key: {value}",
            "STRIPE_KEY={value}",
        ],
    ),
    EntitySpec(
        label="password",
        values_fn=realistic_passwords,
        templates=PASSWORD_TEMPLATES,
        negative_templates=PASSWORD_NEGATIVES,
    ),
    EntitySpec(
        label="db_connection_string",
        values_fn=realistic_db_strings,
        templates=[
            "DATABASE_URL={value}",
            "connect to {value}",
            "the connection string is {value}",
            "use {value} to reach the db",
            "DB_URL={value}",
            "DATABASE_URI={value}",
            "the db url is {value}",
            "url: {value}",
            "MONGO_URI={value}",
            "REDIS_URL={value}",
            "POSTGRES_URL={value}",
            "the connection is {value}",
        ],
    ),
    EntitySpec(
        label="email",
        values_fn=realistic_emails,
        templates=EMAIL_TEMPLATES,
        negative_templates=EMAIL_NEGATIVES,
    ),
    EntitySpec(
        label="ssn",
        regex=r"\d{3}-\d{2}-\d{4}",
        templates=[
            "SSN: {value}",
            "social security number {value}",
            "her ssn is {value}",
            "patient id (ssn) {value}",
            "ssn {value}",
            "social: {value}",
            "ssn = {value}",
            "the ssn on file is {value}",
            "tax id ssn: {value}",
            "applicant ssn {value}",
        ],
        negative_templates=[
            "we don't store SSNs",
            "SSN format is NNN-NN-NNNN",
            "ssn validation rules",
            "remove ssn fields from the form",
        ],
    ),
    EntitySpec(
        label="internal_ip",
        regex=r"(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?",
        templates=[
            "ssh user@{value}",
            "the server is at {value}",
            "connect to {value}:22",
            "internal host {value}",
            "ping {value}",
            "host: {value}",
            "ip: {value}",
            "deploy to {value}",
            "the ip is {value}",
            "10.x range: {value}",
            "internal ip {value}",
            "vpc cidr {value}",
            "private ip {value}",
            "the bastion is {value}",
        ],
    ),
    EntitySpec(
        label="internal_hostname",
        values_fn=realistic_hostnames,
        templates=[
            "the host is {value}",
            "ssh ec2-user@{value}",
            "deploy to {value}",
            "DATABASE_HOST={value}",
            "connect to {value}",
            "internal hostname {value}",
            "host {value}",
            "endpoint: {value}",
            "REDIS_HOST={value}",
            "POSTGRES_HOST={value}",
            "DB_HOST={value}",
            "the prod server is {value}",
            "service endpoint {value}",
            "{value}:5432",
            "{value}:6379",
        ],
    ),
    EntitySpec(
        label="ssh_command",
        values_fn=realistic_ssh_commands,
        templates=[
            "run `{value}` to connect",
            "the deploy command is {value}",
            "{value}",
            "use {value} from the bastion",
            "execute: {value}",
            "first run {value}",
            "to connect: {value}",
            "$ {value}",
            "shell> {value}",
            "command: {value}",
        ],
    ),
    EntitySpec(
        label="private_key_file",
        values=[
            "key.pem", "id_rsa", "id_ed25519", "id_ecdsa", "deploy.pem",
            "~/.ssh/id_rsa", "~/.ssh/prod.pem", "/etc/ssl/private/server.key",
            "prod-deploy.ppk", "ca.p12", "client-cert.pfx", "staging.pem",
            "ci-deploy.pem", "/keys/master.pem", "rsa_4096.pem",
        ],
        templates=[
            "the key file is {value}",
            "ssh -i {value} user@host",
            "load {value} for authentication",
            "private key path: {value}",
            "use key {value}",
            "key location: {value}",
            "-i {value}",
            "ssh_key: {value}",
            "key: {value}",
            "private_key_file: {value}",
        ],
    ),
    EntitySpec(
        label="jwt_token",
        regex=r"eyJ[A-Za-z0-9_-]{20,40}\.eyJ[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{20,40}",
        templates=[
            "Authorization: Bearer {value}",
            "JWT={value}",
            "token: {value}",
            "use this jwt to authenticate: {value}",
            "x-auth-token: {value}",
            "ACCESS_TOKEN={value}",
            "session token {value}",
            "id_token: {value}",
            "bearer {value}",
            "Cookie: jwt={value}",
        ],
    ),
    EntitySpec(
        label="credit_card",
        values_fn=credit_cards,
        templates=[
            "card number: {value}",
            "cc: {value}",
            "credit card {value}",
            "the card on file is {value}",
            "charge to {value}",
            "card: {value}",
            "payment method {value}",
            "saved card {value}",
        ],
        negative_templates=[
            "we accept all major credit cards",
            "credit card validation uses Luhn",
            "PCI compliance for credit card data",
        ],
    ),
]


def make_example(text: str, value: str, label: str) -> dict | None:
    """Locate `value` in `text` and return GLiNER training format with token spans."""
    start = text.find(value)
    if start == -1:
        return None
    end = start + len(value)
    tokens = text.split()
    pos = 0
    tok_start = tok_end = -1
    for i, tok in enumerate(tokens):
        tok_pos = text.find(tok, pos)
        tok_end_pos = tok_pos + len(tok)
        if tok_start == -1 and tok_pos <= start < tok_end_pos:
            tok_start = i
        if tok_pos < end <= tok_end_pos:
            tok_end = i
            break
        pos = tok_end_pos
    if tok_start == -1 or tok_end == -1:
        return None
    return {"tokenized_text": tokens, "ner": [[tok_start, tok_end, label]]}


def gen_for_entity(spec: EntitySpec, target: int) -> tuple[list[dict], int]:
    """Generate `target` examples for one entity type."""
    # Pre-generate a large pool of values.
    if spec.values:
        value_pool = spec.values * (target // len(spec.values) + 1)
    elif spec.values_fn:
        value_pool = spec.values_fn(min(target, 200))
    elif spec.regex:
        value_pool = [exrex.getone(spec.regex) for _ in range(min(target, 500))]
    else:
        return [], 0

    examples: list[dict] = []
    seen = set()
    attempts = 0
    while len(examples) < target and attempts < target * 4:
        attempts += 1
        value = random.choice(value_pool)
        template = random.choice(spec.templates)
        text = template.format(value=value)
        if random.random() < 0.5:  # Wrap with realistic surrounding noise.
            text = add_noise(text)
        if text in seen:
            continue
        seen.add(text)
        ex = make_example(text, value, spec.label)
        if ex:
            examples.append(ex)

    # Add negative examples.
    for tmpl in spec.negative_templates:
        examples.append({"tokenized_text": tmpl.split(), "ner": []})
        examples.append({"tokenized_text": add_noise(tmpl).split(), "ner": []})

    return examples, len(examples)


def gen_multi_entity_examples(n: int) -> list[dict]:
    """Generate examples that mix multiple entity types in one text."""
    multi = []
    spec_by = {s.label: s for s in ENTITIES}
    pairs = [
        ("internal_hostname", "password"),
        ("ssh_command", "private_key_file"),
        ("email", "password"),
        ("aws_access_key", "internal_ip"),
        ("db_connection_string", "password"),
        ("github_token", "internal_hostname"),
    ]
    templates = [
        "host {h} password {p}",
        "the {h} server has password {p}",
        "connect to {h} with password {p}",
        "user {p_label} for {h}: {p}",
    ]
    for _ in range(n):
        e1_label, e2_label = random.choice(pairs)
        e1, e2 = spec_by[e1_label], spec_by[e2_label]
        v1 = (e1.values_fn(50) if e1.values_fn else
              e1.values or [exrex.getone(e1.regex)])
        v2 = (e2.values_fn(50) if e2.values_fn else
              e2.values or [exrex.getone(e2.regex)])
        v1, v2 = random.choice(v1), random.choice(v2)
        text = f"the {e1_label.replace('_', ' ')} is {v1} and the {e2_label.replace('_', ' ')} is {v2}"
        tokens = text.split()
        ner = []
        for v, label in [(v1, e1_label), (v2, e2_label)]:
            start = text.find(v)
            end = start + len(v)
            tok_start = tok_end = -1
            pos = 0
            for i, tok in enumerate(tokens):
                tp = text.find(tok, pos)
                te = tp + len(tok)
                if tok_start == -1 and tp <= start < te:
                    tok_start = i
                if tp < end <= te:
                    tok_end = i
                    break
                pos = te
            if tok_start != -1 and tok_end != -1:
                ner.append([tok_start, tok_end, label])
        if ner:
            multi.append({"tokenized_text": tokens, "ner": ner})
    return multi


def main() -> None:
    examples: list[dict] = []
    stats: dict[str, int] = {}
    for spec in ENTITIES:
        ex, n = gen_for_entity(spec, TARGET_PER_ENTITY)
        examples.extend(ex)
        stats[spec.label] = n
        print(f"  {spec.label:25s} {n}")

    multi = gen_multi_entity_examples(MULTI_ENTITY_EXAMPLES)
    examples.extend(multi)
    print(f"  {'(multi-entity)':25s} {len(multi)}")

    random.shuffle(examples)
    OUTPUT_PATH.write_text(json.dumps(examples))
    print(f"\nTotal: {len(examples)} examples → {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
