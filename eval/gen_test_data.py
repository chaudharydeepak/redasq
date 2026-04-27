"""
Generate a held-out test set with templates/contexts DIFFERENT from training.

Goal: measure how the fine-tuned model generalizes beyond what it saw during
training. Templates here are intentionally varied — different keywords, different
sentence structures, different positioning. We also include adversarial cases
that look similar but should NOT trigger detection.
"""
import json
import random
import string
from pathlib import Path

import exrex

OUTPUT_PATH = Path(__file__).parent / "test_data.json"
RANDOM_SEED = 7  # different from training seed (42)
PER_ENTITY_POSITIVE = 50
PER_ENTITY_NEGATIVE = 20
random.seed(RANDOM_SEED)


# ── Test templates — DIFFERENT from training ─────────────────────────────────
# Training used: "my password is X", "PASSWORD=X", etc.
# Test uses: different phrasings, slack-style, email-style, code comments, etc.

TEST_TEMPLATES = {
    "aws_access_key": [
        # Different from training templates
        "// AWS key for staging: {value}",
        "@channel can someone confirm {value} is still valid?",
        "Please add {value} to vault under team-prod/aws",
        "Found in old config: {value} — should we revoke?",
        "Bot: rotated AWS key, new value {value}",
        "Customer's IAM access key id is {value}",
        "[ERROR] Auth failed with key {value}",
        "After incident #4421, replaced key with {value}",
    ],
    "github_token": [
        "Renewed PAT — new token {value} expires in 90 days",
        "CI is using {value} — gh actions secret",
        "the mcp server uses gh token {value} for repo access",
        "Found leaked token {value} in commit history, revoking",
        "gh-cli authenticated with {value}",
    ],
    "anthropic_key": [
        "Updated .env with new claude key {value}",
        "Per the rotation runbook, set ANTHROPIC_API_KEY to {value}",
        "Claude SDK init: client = Anthropic(api_key='{value}')",
        "ops just sent the new anthropic key {value}",
        "fyi: {value} is the new claude key for the agent service",
    ],
    "openai_key": [
        "Updated openai sdk init with {value}",
        "client = OpenAI(api_key='{value}')",
        "the gpt key in vault path /llm/openai is {value}",
        "rotated openai creds: {value}",
    ],
    "stripe_key": [
        "Stripe webhook authenticated with {value}",
        "Move {value} into the secrets manager",
        "billing service is using {value} — that's the live key",
        "stripe.api_key = '{value}' in payments.py",
    ],
    "password": [
        # Different conversational patterns from training
        "John shared the prod password, it's {value}",
        "I had to use {value} to ssh in",
        "Update README — root pw is now {value}",
        "On-call: the failover password is {value}",
        "@bob what was the pwd again? {value} right?",
        "Just FYI {value} works for the staging admin account",
        "Backup pwd: {value}, store in 1pass",
        "Tested with creds admin/{value} and it worked",
        "Per the runbook, the redis password is {value}",
        "Documented {value} as the temporary deploy password",
    ],
    "db_connection_string": [
        "Sentry caught DATABASE_URL exposed: {value}",
        "Connection string in the .env file: {value}",
        "Migration ran against {value} and failed",
        "@oncall the db url for staging is {value}",
        "Use {value} in your local .env for testing",
    ],
    "email": [
        # Different email phrasings
        "Looping in {value} on the security review",
        "{value} just confirmed the deploy",
        "Slack DM from {value} about the incident",
        "Add {value} to the on-call rotation",
        "Customer ({value}) reported the bug yesterday",
        "Cc {value} on the postmortem doc",
        "{value} owns the auth service",
    ],
    "ssn": [
        "Patient {value} requested medical records",
        "Loan application includes ssn {value}",
        "Verify ssn on file: {value}",
        "Background check: ssn={value}",
        "Tax form shows {value} in the SSN field",
    ],
    "internal_ip": [
        # Different IP usage contexts
        "Tail -f /var/log on {value}",
        "Datadog alert from host {value}",
        "Routing pod traffic via {value}",
        "k8s pod IP is {value}",
        "VPN gateway at {value}",
        "Bastion forwards to {value}",
    ],
    "internal_hostname": [
        # Different hostname usage contexts
        "Postgres failover from {value} to replica",
        "DNS lookup of {value} returns 10.x address",
        "Service mesh routing to {value}",
        "Healthcheck failing on {value}",
        "Deploy succeeded on {value}",
        "Alert: high cpu on {value}",
    ],
    "ssh_command": [
        # Different SSH command contexts
        "I had to run `{value}` to debug the issue",
        "Step 3 in the runbook is: {value}",
        "Just discovered the deploy script does {value}",
        "Manual override: {value} from your dev box",
    ],
    "private_key_file": [
        "Vault path /ssh/keys returns {value}",
        "@here can someone push {value} to the bastion?",
        "Found {value} on a developer laptop, rotating",
        "Deploy needs {value} mounted at /run/secrets",
    ],
    "jwt_token": [
        # Different JWT contexts
        "Frontend got 401, jwt was {value}",
        "Decoded payload from token {value}",
        "Cookie value: session={value}",
        "Bearer auth header: {value}",
        "Refresh token endpoint returned {value}",
    ],
    "credit_card": [
        # Different credit card contexts
        "Customer entered card {value}",
        "Fraud alert on card ending in {value}",
        "Charged ${random_amount} to card {value}",
        "Refund issued for card {value}",
    ],
}


# ── Adversarial negatives — text that LOOKS similar but should NOT match ─────
ADVERSARIAL_NEGATIVES = {
    "aws_access_key": [
        "AWS_ACCESS_KEY_ID is the env var name you should set",
        "configure AWS access via the CLI's aws configure command",
        "use IAM roles instead of static AWS access keys when possible",
    ],
    "github_token": [
        "create a github personal access token via developer settings",
        "github tokens should have minimal scopes",
        "rotate github tokens every 90 days",
    ],
    "password": [
        "the password should be encrypted at rest",
        "implement password complexity requirements",
        "users complain about password policy being too strict",
        "enforce password rotation every 60 days",
        "password validation rejects common patterns",
        "send a password reset email to inactive users",
        "the password manager is the right approach",
    ],
    "email": [
        "validate the email format with a regex",
        "email notifications go through SES",
        "the email field in the form is required",
    ],
    "ssn": [
        "we mask SSNs in logs per HIPAA",
        "SSN is 9 digits in NNN-NN-NNNN format",
        "ssn validation rules are documented in the spec",
    ],
    "internal_ip": [
        "10.0.0.0/8 is reserved for private networks",
        "RFC 1918 defines internal IP ranges",
        "internal IPs should not be in public DNS",
    ],
    "internal_hostname": [
        "internal hostnames should follow naming convention env-service-N.local",
        "DNS for internal hostnames is handled by Route53 private zones",
    ],
    "ssh_command": [
        "ssh into the bastion first, then jump to the target",
        "use ssh-agent forwarding for key management",
        "ssh keepalive is configured at 60 seconds",
    ],
    "credit_card": [
        "credit card validation uses the Luhn algorithm",
        "PCI DSS scope includes anything touching credit card data",
        "we never store full credit card numbers",
    ],
}


def realistic_passwords(n: int) -> list[str]:
    """Different from training — focus on realistic developer-style passwords."""
    bases = ["Vault", "Secret", "Master", "Backup", "Failover", "Recovery",
             "Deploy", "Cluster", "Worker", "Bastion"]
    suffixes = ["@deploy24", "_temp_99", "!new2026", "@rotation",
                "$prod_42", "#staging-1", "%fallback"]
    out = set()
    while len(out) < n:
        body = random.choice(bases) + str(random.randint(10, 99))
        body += "".join(random.choices(string.ascii_lowercase, k=random.randint(2, 4)))
        body += random.choice(suffixes)
        out.add(body)
    return list(out)


def realistic_emails(n: int) -> list[str]:
    """Different combinations from training set."""
    firsts = ["nina", "oscar", "petra", "quinn", "raj", "sam", "tess",
              "uma", "viktor", "wendy", "xander", "yara", "zoe"]
    lasts = ["nguyen", "anderson", "kowalski", "martinez", "okonkwo",
             "papadopoulos", "ramirez", "tanaka", "vasquez"]
    domains = ["enterprise.com", "corp.io", "globalcorp.net", "techcorp.dev",
               "scaleup.ai", "biotech.com", "fintech.io"]
    out = set()
    while len(out) < n:
        f, l, d = random.choice(firsts), random.choice(lasts), random.choice(domains)
        sep = random.choice([".", "_", ""])
        out.add(f"{f}{sep}{l}@{d}")
    return list(out)


def realistic_hostnames(n: int) -> list[str]:
    """New service/env combos not in training."""
    services = ["audit", "metrics", "logging", "queue-processor", "scheduler",
                "notifier", "billing-svc", "user-service", "order-api",
                "inventory", "shipping", "warehouse", "backup-runner"]
    envs = ["eu-prod", "us-west-staging", "canary", "blue", "green", "shadow"]
    suffixes = [".internal.eu", ".staging.local", ".eks.cluster.local",
                ".internal.gcp", ".prod.acme.io"]
    out = set()
    while len(out) < n:
        s, e = random.choice(services), random.choice(envs)
        out.add(f"{s}-{e}{random.choice(suffixes)}")
    return list(out)


def realistic_db_strings(n: int) -> list[str]:
    schemes = ["postgresql", "mysql", "mongodb+srv", "redis"]
    users = ["app", "service", "lambda_fn", "etl_job", "reporting"]
    pwds = ["DiffPwd!42", "ProdSecret2024", "StagingPw#1", "BackupKey99"]
    hosts = realistic_hostnames(20)
    dbs = ["analytics_v2", "events_warehouse", "billing_history", "audit_log"]
    out = set()
    while len(out) < n:
        scheme = random.choice(schemes)
        user, pwd = random.choice(users), random.choice(pwds)
        host = random.choice(hosts)
        db = random.choice(dbs)
        out.add(f"{scheme}://{user}:{pwd}@{host}/{db}")
    return list(out)


def realistic_ssh_commands(n: int) -> list[str]:
    users = ["jenkins", "gitlab-runner", "ci-deploy", "ansible", "terraform"]
    keys = ["ci.pem", "jenkins.key", "ansible-deploy.pem", "tf-state.pem"]
    hosts = realistic_hostnames(15)
    out = set()
    while len(out) < n:
        u, h, k = random.choice(users), random.choice(hosts), random.choice(keys)
        out.add(f"ssh -i {k} {u}@{h}")
    return list(out)


def credit_cards(n: int) -> list[str]:
    """Luhn-valid numbers different from training."""
    prefixes = ["4242", "5555", "5454", "378282", "601100"]
    out = set()
    while len(out) < n:
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
        out.add(body + str(check))
    return list(out)


VALUE_GENERATORS = {
    "aws_access_key":      lambda n: [exrex.getone(r"AKIA[A-Z0-9]{16}") for _ in range(n)],
    "github_token":        lambda n: [exrex.getone(r"ghp_[A-Za-z0-9]{36}") for _ in range(n)],
    "anthropic_key":       lambda n: [exrex.getone(r"sk-ant-api03-[A-Za-z0-9_-]{40}") for _ in range(n)],
    "openai_key":          lambda n: [exrex.getone(r"sk-(?:proj-)?[A-Za-z0-9_-]{40}") for _ in range(n)],
    "stripe_key":          lambda n: [exrex.getone(r"sk_(?:live|test)_[A-Za-z0-9]{24}") for _ in range(n)],
    "password":            realistic_passwords,
    "db_connection_string": realistic_db_strings,
    "email":               realistic_emails,
    "ssn":                 lambda n: [exrex.getone(r"\d{3}-\d{2}-\d{4}") for _ in range(n)],
    "internal_ip":         lambda n: [exrex.getone(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}") for _ in range(n)],
    "internal_hostname":   realistic_hostnames,
    "ssh_command":         realistic_ssh_commands,
    "private_key_file":    lambda n: random.choices(
        ["aws-deploy.pem", "k8s-master.key", "vault-unseal.pem", "ci-cd.pem",
         "etcd-peer.crt", "client.p12", "operator.pfx"], k=n),
    "jwt_token":           lambda n: [exrex.getone(
        r"eyJ[A-Za-z0-9_-]{20,40}\.eyJ[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{20,40}"
    ) for _ in range(n)],
    "credit_card":         credit_cards,
}


def make_example(text: str, value: str, label: str) -> dict | None:
    """Find value in text, return GLiNER-format example with token spans + char spans."""
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
    return {
        "text": text,
        "tokenized_text": tokens,
        "ner": [[tok_start, tok_end, label]],
        "expected_value": value,
        "expected_label": label,
    }


def main() -> None:
    examples: list[dict] = []
    counts = {}
    for label, templates in TEST_TEMPLATES.items():
        gen = VALUE_GENERATORS[label]
        values = gen(PER_ENTITY_POSITIVE)
        n = 0
        for value in values:
            template = random.choice(templates)
            if "{random_amount}" in template:
                template = template.replace("{random_amount}", str(random.randint(10, 9999)))
            text = template.format(value=value)
            ex = make_example(text, value, label)
            if ex:
                examples.append(ex)
                n += 1
        # Adversarial negatives (text mentioning the keyword but NO value to detect).
        for adv in ADVERSARIAL_NEGATIVES.get(label, []):
            examples.append({
                "text": adv,
                "tokenized_text": adv.split(),
                "ner": [],
                "expected_value": None,
                "expected_label": label,  # the label this adversarial is testing
                "adversarial": True,
            })
        counts[label] = n

    random.shuffle(examples)
    OUTPUT_PATH.write_text(json.dumps(examples, indent=2))
    print(f"Wrote {len(examples)} test examples to {OUTPUT_PATH}")
    for label, n in sorted(counts.items()):
        n_adv = len(ADVERSARIAL_NEGATIVES.get(label, []))
        print(f"  {label:25s} pos={n:3d}  adversarial={n_adv}")


if __name__ == "__main__":
    main()
