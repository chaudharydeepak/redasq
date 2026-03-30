# Prompt Guard

A lightweight HTTPS MITM proxy that intercepts prompts sent to AI coding assistants and APIs — blocking or redacting sensitive data before it leaves your machine.

![Prompt Guard demo](demo.gif)

## Why

AI tools like GitHub Copilot, ChatGPT, and Claude receive your full editor context. That context can contain API keys, passwords, SSNs, internal IP addresses, and other secrets — sent to third-party servers without you noticing. Prompt Guard sits between your tools and the AI APIs, inspects every prompt in real time, and blocks or redacts sensitive data before it is forwarded.

## Features

- **HTTPS MITM proxy** — transparent interception using a local CA cert
- **Real-time inspection** — rules run on every prompt before it's forwarded
- **Block mode** — request is rejected; the AI receives a "blocked" message instead
- **Redact mode** — sensitive value is replaced with `[REDACTED]` before forwarding; the AI still responds
- **Web dashboard** — live feed of all intercepted prompts with matched snippets and status
- **12 built-in rules** — credentials, PII, tokens, private keys
- **Live rule editing** — change rule modes in the dashboard; changes are written back to `rules.json` instantly
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

| Rule | Severity | Default Mode |
|---|---|---|
| AWS Access Key (`AKIA…`) | High | Block |
| AWS Secret Key | High | Block |
| OpenAI API Key (`sk-…`) | High | Block |
| Anthropic API Key (`sk-ant-…`) | High | Block |
| GitHub Token (`ghp_`, `gho_`, …) | High | Block |
| Private Key (PEM block) | High | Block |
| Social Security Number | High | Block |
| Credit Card Number | High | Block |
| JWT Token | Medium | Track |
| Generic Secret / Password assignment | Medium | Track |
| Email Address | Low | Track |
| Internal IP Address (RFC-1918) | Low | Track |

**Block** — request is rejected; nothing is forwarded to the AI.
**Track** — matched value is replaced with `[REDACTED]` in the forwarded request; the AI responds to the sanitised prompt.

Rules can be switched between modes at any time from the dashboard without restarting.

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

Install CA (run once):
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain ~/.prompt-guard/ca.crt

Set proxy:
  export HTTP_PROXY=http://localhost:8080
  export HTTPS_PROXY=http://localhost:8080
  export NO_PROXY=localhost,127.0.0.1

Dashboard:  http://localhost:7778
Rules file: /Users/you/.prompt-guard/rules.json
```

### Using with VS Code Copilot

The most reliable way is to set the proxy directly in VS Code settings (`Cmd+,`):

```json
"http.proxy": "http://localhost:8080",
"http.proxyStrictSSL": true
```

Then restart VS Code. Traffic from all Copilot models (Claude, GPT-4o, etc.) will flow through the proxy.

### Using with Claude CLI

Node.js ignores the system keychain, so pass the CA cert explicitly:

```bash
export NODE_EXTRA_CA_CERTS=~/.prompt-guard/ca.crt
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
claude
```

To avoid setting these every session, add them to your `~/.zshrc` (or `~/.bashrc`).

### Using with curl / scripts

```bash
curl --proxy http://localhost:8080 https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## Customizing Rules

Rules are configured in `~/.prompt-guard/rules.json`. The file is created automatically when you first change a rule mode in the dashboard. You can also create or edit it manually — changes take effect on the next proxy restart.

**Override a built-in rule** (e.g. switch email from track to block):

```json
{
  "overrides": [
    { "id": "email", "mode": "block" },
    { "id": "jwt-token", "severity": "high" }
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
--port       Proxy port (default: 8080)
--web-port   Dashboard port (default: 7778)
--ca-dir     Directory for CA cert, key, and database (default: ~/.prompt-guard)
```

## Architecture

```
Your app (VS Code, curl, etc.)
  → HTTP_PROXY / HTTPS_PROXY
    → prompt-guard proxy (:8080)
      ├── Non-target hosts → blind tunnel (unchanged)
      └── Target hosts (OpenAI, Anthropic, Copilot)
            → TLS MITM (local CA cert)
              → parse JSON body → extract user prompt text
                → run rules
                  ├── block match  → reject request; return block message to client
                  ├── track match  → redact value in body; forward sanitised request
                  └── clean        → forward unchanged
                → store in SQLite (prompt, status, matched snippets)
                  → web dashboard (:7778) reads SQLite
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
│   ├── rules.go         Built-in rules (regex + metadata)
│   └── config.go        rules.json loading and write-back
├── store/
│   └── store.go         SQLite persistence
└── web/
    └── web.go           Web dashboard (embedded HTML)
```

## License

AGPL
