<p align="center">
  <img src="logo.svg" width="120" alt="Prompt Guard">
</p>

# Prompt Guard

A lightweight HTTPS MITM proxy that intercepts prompts sent to AI coding assistants and APIs — blocking or redacting sensitive data before it leaves your machine.

![Prompt Guard demo](demo.gif)

## Why

AI tools like GitHub Copilot, ChatGPT, and Claude receive your full editor context. That context can contain API keys, passwords, SSNs, internal IP addresses, and other secrets — sent to third-party servers without you noticing. Prompt Guard sits between your tools and the AI APIs, inspects every prompt in real time, and blocks or redacts sensitive data before it is forwarded.

The risk is well-documented:

- [GitGuardian State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/) — 29M secrets exposed on public GitHub; AI-service leaks up 81% YoY
- [AI Coding Assistants Drive Surge in Secret Leaks](https://oecd.ai/en/incidents/2026-03-17-2273) — Claude Code-assisted commits leak secrets at 2× the rate of human developers
- [How AI Assistants Leak Secrets in Your IDE](https://www.knostic.ai/blog/ai-coding-assistants-leaking-secrets) — practical breakdown of how IDE context ends up in AI API requests
- [Researchers Uncover 30+ Flaws in AI Coding Tools](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) — data theft and RCE via prompt injection in Cursor and similar tools
- [AI-assisted coding and unsanctioned tools headline 2026's biggest security risks](https://leaddev.com/ai/ai-assisted-coding-and-unsanctioned-tools-headline-2026s-biggest-security-risks) — LeadDev on the organisational risk of unmonitored AI tool usage

## Features

- **HTTPS MITM proxy** — transparent interception; CA cert optional (required only for browser inspection)
- **Real-time inspection** — rules run on every prompt before it's forwarded
- **Block mode** — request is rejected; the AI receives a "blocked" message instead. Because the prompt is never forwarded, the sensitive data leaves no trace in the model's context — even across a long-running session
- **Redact mode** — sensitive value is replaced with `[REDACTED]` before forwarding; the AI still responds
- **Web dashboard** — live feed of all intercepted prompts with matched snippets, status, token usage, session ID, and client identity

![Prompt Guard Dashboard](dashboard.png)
- **230 built-in rules** — powered by the [gitleaks](https://github.com/gitleaks/gitleaks) rule database plus hand-rolled rules for PII and credentials
- **Live rule editing** — change rule modes in the dashboard; changes are written back to `rules.json` instantly
- **Agent mode** — one-click toggle to switch all rules to redact so long-running agents are never hard-blocked; state persists across restarts; each request tagged in the dashboard
- **SQLite persistence** — full audit log across restarts
- **Single binary** — no runtime dependencies

## Targets

Intercepts prompts sent to:

| Service | Host |
|---|---|
| GitHub Copilot | `*.githubcopilot.com` |
| OpenAI | `api.openai.com` |
| Anthropic | `api.anthropic.com` |

All other HTTPS traffic is tunnelled through unchanged.

## Built-in Rules

Prompt Guard ships with **230 rules** across two sources:

### gitleaks rules (221)

Patterns are derived from the [gitleaks](https://github.com/gitleaks/gitleaks) secret detection rule database (MIT License) — the same battle-tested ruleset used by GitHub's secret scanning. Rules cover service-specific tokens and credentials for over 200 providers including AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, and more.

| Severity | Mode | Count | What it covers |
|---|---|---|---|
| High | Block | 213 | Service-specific tokens with known prefixes (e.g. `AKIA…`, `ghp_…`, `sk-ant-api03-…`) |
| Medium | Block | 8 | Broad structural patterns: generic API key assignments, curl credentials, k8s Secret YAML, JWTs |

### Hand-rolled rules (9)

| Rule | Severity | Mode |
|---|---|---|
| Social Security Number | High | Block |
| Credit Card Number (Luhn-validated) | High | Block |
| Database Connection String | High | Block |
| HTTP Basic Auth credential | High | Block |
| HTTP Bearer token | High | Block |
| Generic Secret / Password assignment | Medium | Block |
| Email Address | Low | Track |
| Internal IP Address (RFC-1918) | Low | Track |

**Block** — request is rejected; nothing is forwarded to the AI.
**Track** — matched value is replaced with `[REDACTED]` in the forwarded request; the AI responds to the sanitised prompt.

All rules are visible in the dashboard and can be switched between modes at any time without restarting. Mode changes are written back to `rules.json` immediately.

### Updating gitleaks patterns

To pull in new rules from a future gitleaks release:

```bash
curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/main/config/gitleaks.toml \
     -o /tmp/gitleaks.toml
python3 scripts/gen_rules.py /tmp/gitleaks.toml > inspector/rules.go
go build ./...
```

## Requirements

- Go 1.21+
- macOS, Linux, or Windows

## Quickstart

```bash
git clone https://github.com/chaudharydeepak/prompt-guard
cd prompt-guard
go build -o prompt-guard .
./prompt-guard
```

On first run a local CA cert is generated and setup instructions are printed:

```
┌─────────────────────────────────────────┐
│           Prompt Guard starting         │
└─────────────────────────────────────────┘

CA cert:   /Users/you/.prompt-guard/ca.crt

Install CA (optional — only needed for browser inspection):
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain ~/.prompt-guard/ca.crt

Set proxy:
  export HTTP_PROXY=http://localhost:8080
  export HTTPS_PROXY=http://localhost:8080
  export NO_PROXY=localhost,127.0.0.1

Dashboard:  http://localhost:7778
Rules file: /Users/you/.prompt-guard/rules.json
```

The CA cert is **not required** for most CLI tools. Only install it if you want to route traffic from a browser or tool that does its own TLS certificate verification.

### Using with Claude CLI / Claude Code

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
export NODE_EXTRA_CA_CERTS=~/.prompt-guard/ca.crt
claude
```

`NODE_EXTRA_CA_CERTS` is required for Claude Code v2.1.84+ — newer versions verify TLS certificates and will reject the MITM cert without it. This variable scopes the trust to Node.js processes only (no system keychain changes needed).

Add all four lines to your `~/.zshrc` (or `~/.bashrc`) to persist across sessions.

### Using with VS Code Copilot

Set the proxy directly in VS Code settings (`Cmd+,`):

```json
"http.proxy": "http://localhost:8080",
"http.proxyStrictSSL": false
```

Then restart VS Code. Traffic from all Copilot models will flow through the proxy.


## Agent Mode

When running long-lived agentic workflows (Claude Code, Cursor agents, automated pipelines), requests may get hard-blocked mid-task if sensitive data appears in the conversation context — causing the agent to fail.

**Agent Mode** solves this. Toggle it from the dashboard header:

- **OFF (default)** — rules fire as configured. Block-mode rules reject the request outright; the agent or IDE receives an error and stops.
- **ON** — all rules switch to redact. Sensitive values are masked with `[REDACTED]` before the request is forwarded, but the request always goes through. The agent keeps running.

Sensitive data is still protected in both modes — the difference is whether a matched value stops the request or is silently redacted.

Agent mode state persists across proxy restarts. Each intercepted request is tagged in the dashboard so you can see which calls were made while agent mode was active.

**When to use agent mode OFF:** if you want strict enforcement and are OK with agents being interrupted when sensitive data is detected — for example, during a code review or one-off task where you want to know immediately if something sensitive is being sent.

## Customizing Rules

Rules are configured in `~/.prompt-guard/rules.json`. The file is created automatically when you first change a rule mode in the dashboard. You can also create or edit it manually — changes take effect on the next proxy restart.

**Override a built-in rule** (e.g. switch email from track to block):

```json
{
  "overrides": [
    { "id": "email", "mode": "block" },
    { "id": "generic-api-key", "severity": "high" }
  ]
}
```

**Add a custom rule**:

```json
{
  "rules": [
    {
      "id": "my-internal-token",
      "name": "Acme Internal Token",
      "description": "Internal service token format",
      "pattern": "ACME-[A-Z0-9]{32}",
      "severity": "high",
      "mode": "block"
    }
  ]
}
```

Changes made in the dashboard are written back to `rules.json` automatically and survive restarts.

## Options

```
--port            Proxy port (default: 8080)
--web-port        Dashboard port (default: 7778)
--ca-dir          Directory for CA cert, key, and database (default: ~/.prompt-guard)
--upstream-proxy  Corporate proxy to chain through (e.g. http://proxy.corp.com:8080)
--debug           Enable verbose request/connection logging
```

### Corporate proxy chaining

If you're behind a corporate proxy, pass it via `--upstream-proxy`:

```bash
./prompt-guard --upstream-proxy http://proxy.corp.com:8080
```

With basic auth:

```bash
./prompt-guard --upstream-proxy http://user:pass@proxy.corp.com:8080
```

Prompt Guard will CONNECT through the corporate proxy for all outbound traffic, while still intercepting AI API requests.

## Architecture

```mermaid
flowchart TD
    Client["🖥️ AI Client\n(VS Code · Claude CLI · curl)"]
    PG["🛡️ Prompt Guard\n:8080"]
    Rules["230 Detection Rules\n(gitleaks + hand-rolled)"]
    DB[("SQLite\naudit log")]
    Dashboard["📊 Dashboard\n:7778"]
    LLM["☁️ LLM APIs\n(OpenAI · Anthropic · Copilot)"]
    Blocked["❌ Blocked\nError returned to client\nNothing forwarded"]
    Redacted["✂️ Redacted\nSecret replaced with [REDACTED]\nSanitised prompt forwarded"]
    Clean["✅ Clean\nForwarded unchanged"]

    Client -->|"HTTPS prompt\nvia HTTP_PROXY"| PG
    PG -->|"decrypt · extract text"| Rules
    Rules -->|"block match"| Blocked
    Rules -->|"track match"| Redacted
    Rules -->|"no match"| Clean
    Blocked -->|"log"| DB
    Redacted -->|"log + forward"| LLM
    Clean -->|"log + forward"| LLM
    DB --> Dashboard
```

```
prompt-guard/
├── main.go              CLI entrypoint
├── proxy/
│   ├── ca.go            Local CA cert generation and leaf cert signing
│   ├── proxy.go         HTTP CONNECT handler, TLS MITM, request forwarding
│   └── intercept.go     Prompt extraction from OpenAI / Anthropic JSON bodies
├── inspector/
│   ├── engine.go        Rule matching engine (block, redact, snippet capture)
│   ├── rules.go         Built-in rules (230 rules; hand-rolled + gitleaks-derived)
│   └── config.go        rules.json loading and write-back
├── store/
│   └── store.go         SQLite persistence
├── web/
│   └── web.go           Web dashboard (embedded HTML)
└── scripts/
    └── gen_rules.py     Converts gitleaks.toml → inspector/rules.go
```

## License

AGPL
