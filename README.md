# InjectionForge Pro X v1.1.5

Production-ready open-source framework for authorized prompt-injection, chatbot security, and sensitive-disclosure testing.

[![CI](https://github.com/Mafifrizi/InjectionForgeProX/actions/workflows/ci.yml/badge.svg)](https://github.com/Mafifrizi/InjectionForgeProX/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-58%20pytest%20tests-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.5-orange)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

## Overview

InjectionForge Pro X is a security testing framework for evaluating LLM-powered chatbots, AI agents, and conversational APIs against prompt injection, instruction override, and sensitive information disclosure risks.

The framework is designed for:

- Internal security assessments.
- Developer validation before releasing AI/chatbot features.
- Authorized bug bounty testing where AI/chatbot testing is in scope.
- Lab environments and CTF-style training.
- Regression testing of AI safety controls.

The project includes multilingual payload support, evidence-gated detection, report redaction, configuration profiles, CI checks, rate limiting, and multiple connector types.

Use this tool only on systems where you have explicit authorization.

## Table of Contents

- [Overview](#overview)
- [Authorization Notice](#authorization-notice)
- [Key Capabilities](#key-capabilities)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Validation Before Use](#validation-before-use)
- [Recommended Workflow](#recommended-workflow)
- [Command Reference](#command-reference)
- [Configuration Profiles](#configuration-profiles)
- [Target Examples](#target-examples)
- [Analyzer Modes](#analyzer-modes)
- [Language Modes](#language-modes)
- [Rate Limiting](#rate-limiting)
- [Report Redaction](#report-redaction)
- [Output Formats](#output-formats)
- [Validation Dataset](#validation-dataset)
- [GitHub Actions CI](#github-actions-ci)
- [Project Structure](#project-structure)
- [Operational Guidance](#operational-guidance)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Authorization Notice

InjectionForge Pro X can generate adversarial prompts and test sensitive-disclosure behavior. Only use it against targets that you own, operate, or are explicitly authorized to test.

For real targets, use the `--authorized` flag to acknowledge authorization:

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --authorized
```

The flag is not a legal bypass. It is a safety reminder and workflow marker. You are responsible for following the target's program rules, rate limits, and testing boundaries.

## Key Capabilities

| Capability | Description |
|------------|-------------|
| Multi-protocol connectors | REST, GraphQL, WebSocket, SSE, Ollama, OpenAI, Claude, Gemini, Cohere, HuggingFace, and mock target. |
| Multilingual testing | English, Bahasa Indonesia, mixed-language, and automatic language mode. |
| Evidence-gated analyzer | Avoids naive keyword-only detection. Requires concrete evidence before marking a finding as successful. |
| Analysis modes | `strict`, `balanced`, and `sensitive` modes for different testing phases. |
| FP/FN regression dataset | 171 labeled cases covering leaks, refusals, redacted values, benign echoes, examples, placeholders, and mixed-language responses. |
| Redaction and safe persistence | Redacts report output and runtime SQLite result storage by default, including analyzer-extracted literals. |
| Rate limiting | Global token-bucket limiter shared across worker threads. |
| Profiles | JSON/YAML profiles for repeatable target configuration. |
| CI workflow | GitHub Actions workflow for compile checks, tests, analyzer validation, and benchmark evaluation. |
| Multiple report formats | JSON, HTML, CSV, PDF, XLSX, and terminal output. |

## Installation

### Requirements

- Python 3.10 or newer.
- Windows, Linux, or macOS.
- Internet access only if you use vendor LLM APIs, headless browser mode, or optional model downloads.

### Standard Installation

```bash
git clone https://github.com/Mafifrizi/InjectionForgeProX.git
cd InjectionForgeProX
pip install -r requirements.txt
```

### Dependency policy

The project uses bounded compatible ranges for every direct dependency. This prevents an unreviewed major-version upgrade while keeping installation practical across supported Python platforms. For an immutable deployment, resolve these ranges into a hash-locked environment after validating the target platform:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
```

The optional browser-backed WAF workflow requires extra dependencies:

```bash
pip install -e ".[browser]"
```

Headless browser mode requires Playwright browser assets:

```bash
playwright install
```

Only install Playwright browsers if you intend to use `--headless` or browser-assisted WAF handling.

### Editable Developer Installation

```bash
pip install -e .[test]
injectionforge --version
```

This installs the project in editable mode and enables the console entry point.

### Windows PowerShell Notes

PowerShell supports line continuation with backticks:

```powershell
python forge_x.py --target mock `
  --analysis-mode strict `
  --language auto `
  --offline
```

Alternatively, run the command on one line.

## Quick Start

### 1. Run the mock target

Use this first to verify that the tool is working locally:

```bash
python forge_x.py --target mock --rounds 5 --offline
```

### 2. Run a strict mock test with profile

```bash
python forge_x.py --profile examples/profiles/mock-strict.json
```

### 3. Generate an HTML report

```bash
python forge_x.py --target mock --rounds 5 \
  --format html --output reports/mock-report.html --offline
```

The `reports/` directory is created automatically when a report is written. Report files are runtime artifacts and should not be committed.

### 4. Run analyzer validation

```bash
python forge_x.py --validate --light --offline --analysis-mode balanced
```

### 5. Run strict benchmark evaluation

```bash
python evaluate.py --analysis-mode strict
```

## Validation Before Use

Before using the tool on a real target or before pushing changes, run:

```bash
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
python forge_x.py --version
python forge_x.py --profile examples/profiles/mock-strict.json --rounds 2
```

Expected baseline:

```text
pytest: 58 tests passed
Analyzer validation: quality gate passed
Benchmark: 100% precision and 100% recall on bundled regression dataset
Version: InjectionForge Pro X 1.1.1
Profile mode: campaign runs successfully
```

The bundled dataset is a regression benchmark. It does not guarantee zero false positives or zero false negatives on every real-world LLM target.

## Recommended Workflow

### Phase 1: Safe Recon

Use a small number of rounds, low worker count, and rate limiting.

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode balanced \
  --audit --rounds 10 --workers 1 --rate-limit 1 --burst 1 \
  --timeout 20 --format json --output reports/recon.json \
  --offline --authorized
```

Purpose:

- Confirm that the endpoint works.
- Confirm the correct `--json-path`.
- Observe normal response behavior.
- Avoid overloading the target.

### Phase 2: Candidate Discovery

Use `sensitive` mode when looking for potential findings. This mode is designed to reduce false negatives, so manual review is required.

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode sensitive \
  --category advanced --rounds 30 --workers 2 --rate-limit 1 --burst 1 \
  --timeout 25 --format json --output reports/candidates.json \
  --offline --authorized
```

Purpose:

- Find possible prompt-injection or disclosure candidates.
- Collect enough evidence for manual review.
- Avoid treating early candidates as final findings.

### Phase 3: Strict Retest

Use `strict` mode for final validation.

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode strict \
  --audit --rounds 20 --workers 1 --rate-limit 1 --burst 1 \
  --timeout 25 --diff --format html --output reports/final.html \
  --offline --authorized
```

Purpose:

- Reduce false positives.
- Confirm that evidence is concrete.
- Produce a report suitable for internal review or authorized bug bounty triage.

### Phase 4: Manual Reproduction

Before reporting a finding:

1. Reproduce it manually with the minimum payload.
2. Verify the impact.
3. Confirm the behavior is not a harmless echo or placeholder.
4. Keep report redaction enabled unless the report is stored securely.
5. Follow the target's disclosure policy.

## Command Reference

### Profile and Safety Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--profile` | file path | Load JSON/YAML target profile. CLI flags override profile values. |
| `--authorized` | boolean | Confirms that the operator is authorized to test the target. |
| `--version` | boolean | Print tool version and exit. |

### Target and Connection Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--target` | `auto`, `mock`, `custom`, `openai`, `claude`, `gemini`, `cohere`, `ollama`, `huggingface`, `graphql` | Target connector type. |
| `--endpoint` | URL | Target API, WebSocket, SSE, GraphQL, or page URL. |
| `--method` | `POST`, `GET`, `WS`, `SSE` | Request method or streaming protocol. |
| `--headers` | JSON or `Key:Value` | Additional request headers. |
| `--cookie` | string or file | Cookie string or file path. |
| `--json-path` | path | Field containing response text, for example `reply`, `data.text`, or `choices.0.message.content`. |
| `--form` | boolean | Send payload as form-encoded body. |
| `--timeout` | seconds | Request timeout. |
| `--proxy` | URL | HTTP/SOCKS proxy. |
| `--insecure` | boolean | Disable TLS verification for authorized internal testing. |
| `--api-key` | string | API key for vendor LLM connectors. Prefer environment variables or secure secret storage. |
| `--model` | string | Model name for Ollama, HuggingFace, or vendor connectors. |

### Authentication and Session Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--csrf-token` | URL or token | Fetch or provide CSRF token. |
| `--auth-endpoint` | URL | Endpoint used to fetch auth token. |
| `--auth-data` | JSON or key-value | Auth request body. |
| `--login` | URL | Login form URL for auto-login flow. |
| `--username` | string | Username for login flow. |
| `--password` | string | Password for login flow. |

Do not commit secrets, cookies, API keys, or generated report files.

### Language and Analyzer Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--language` | `auto`, `en`, `id`, `mixed` | Payload and analyzer language mode. |
| `--analysis-mode` | `strict`, `balanced`, `sensitive` | Analyzer decision mode. |
| `--validate` | boolean | Run analyzer validation dataset. |
| `--light` | boolean | Use lightweight validation behavior. |
| `--offline` | boolean | Avoid model downloads and use deterministic checks. |
| `--llm-judge` | Ollama URL | Optional confirmatory local LLM judge. |

### Payload and Campaign Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--category` | `basic`, `advanced`, `indirect`, `agent`, `graphql` | Payload category. |
| `--rounds` | integer | Number of attempts. |
| `--mutate` | boolean | Enable standard payload mutation. |
| `--aggressive` | boolean | Enable aggressive mutation and generator fallback. Use carefully on real targets. |
| `--audit` | boolean | Use audit-oriented payload selection. Recommended for real targets. |
| `--adaptive` | boolean | Enable adaptive payload weighting. |
| `--multi-stage` | boolean | Enable priming plus exploitation flow. |
| `--history` | file path | JSON conversation history file. |
| `--workers` | integer | Worker thread count. |
| `--rate-limit` | number | Global request rate limit across all workers. |
| `--burst` | integer | Token-bucket burst size. |
| `--ai-payloads` | boolean | Generate target-aware assessment probes with a local LLM, retrieve validated prior probes for the same target scope, and retain analyzer-confirmed successes. |
| `--ai-only` | boolean | Skip the template baseline and run only local AI-generated probes. Requires `--ai-payloads`. |
| `--ai-generator-url` | URL | Local Ollama URL for adaptive AI probe generation. |
| `--ai-generator-model` | model | Local model name for adaptive AI probe generation. |
| `--ai-generator-timeout` | seconds | Local AI generation timeout; defaults to 8 seconds before safe fallback probes are used. |

### Attack Tree and Adaptive Agent Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--attack-tree` | boolean | Run adaptive attack-tree mode. |
| `--max-depth` | integer | Attack-tree depth. Keep low for real targets. |
| `--adaptive-agent` | boolean | Run adaptive multi-turn agent. More exploratory and noisier than audit mode. |
| `--target-description` | string | Manual target description for adaptive agent. |

### WAF, Stealth, and Discovery Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--bypass-waf` | `cloudflare`, `akamai`, `auto`, `none` | WAF bypass strategy. Use only if explicitly allowed. |
| `--tls-fingerprint` | `random`, `chrome`, `firefox`, `safari` | TLS fingerprint profile where supported. |
| `--headless` | boolean | Use headless browser support. |
| `--stealth` | boolean | Enable User-Agent rotation and jitter. |
| `--delay` | seconds | Base delay between requests. |
| `--discover` | boolean | Auto-discover chat endpoints from a page. |
| `--auto-profile` / `--no-auto-profile` | boolean | Enable or disable target profiling. Disabled by default; enable it only when profiling probes are authorized. |
| `--discover-external` | boolean | Permit discovery to follow external script/endpoint references. Disabled by default to prevent unintended cross-origin requests. |
| `--waf-detect` | boolean | Detect WAF without running a campaign. |
| `--graphql-introspect` | boolean | Run GraphQL introspection where authorized. |

### Output Flags

| Flag | Values | Description |
|------|--------|-------------|
| `--format` | `json`, `html`, `csv`, `pdf`, `xlsx`, `term` | Report format. |
| `--output` | file path | Output report path. |
| `--redact` | boolean | Enable report redaction. Disabled by default; enable it only when profiling probes are authorized. |
| `--no-redact` | boolean | Disable report redaction. Use only when safe. |
| `--diff` | boolean | Compare response with a neutral baseline. |

## Configuration Profiles

Profiles reduce operator mistakes during repeated engagements. They are useful when a target needs many flags such as headers, method, JSON path, rate limit, and output settings.

Run with a profile:

```bash
python forge_x.py --profile examples/profiles/mock-strict.json
```

CLI flags override profile values:

```bash
python forge_x.py --profile examples/profiles/mock-strict.json --rounds 2
```

### Example Profile

```json
{
  "target": "custom",
  "endpoint": "https://api.example.com/chat",
  "method": "POST",
  "json-path": "reply",
  "headers": {
    "Authorization": "Bearer REPLACE_ME"
  },
  "language": "auto",
  "analysis-mode": "strict",
  "audit": true,
  "rounds": 20,
  "workers": 2,
  "rate-limit": 1,
  "burst": 1,
  "offline": true,
  "authorized": true,
  "format": "html",
  "output": "reports/final.html"
}
```

### Profile Tips

- Keep real secrets out of committed profile files.
- Use placeholders such as `REPLACE_ME` in examples.
- Keep one profile per engagement or target environment.
- Prefer `strict` mode for final validation profiles.
- Prefer `rate-limit` for small or sensitive production systems.

## Adaptive AI Probe Generation

`--ai-payloads` adds a local-model generation layer; it is not a replacement for validation. The engine derives a non-secret target description when one is not supplied, retrieves previously validated probes for the same target fingerprint, generates bounded assessment probes through a local Ollama model, and stores only analyzer-confirmed successes with redacted metadata.

The default is hybrid: a short deterministic baseline can establish behavior, then AI-generated probes add target-aware coverage. Use `--ai-only` when an authorized engagement explicitly requires generated probes without the template baseline.

```bash
# Hybrid baseline plus generated probes
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --ai-payloads \
  --ai-generator-url "http://localhost:11434" --ai-generator-model llama3 \
  --rounds 10 --workers 1 --rate-limit 1 --authorized --offline

# Generated probes only; use on an explicitly authorized target
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --ai-payloads --ai-only \
  --target-description "customer-support assistant with retrieval" \
  --rounds 10 --workers 1 --rate-limit 1 --authorized --offline
```

The generator is deliberately constrained to synthetic assessment markers and must not be treated as a mechanism for requesting real credentials or confidential data. The retained database stores payload metadata and evidence summaries, not raw target responses.

## Target Examples

### Mock Target

```bash
python forge_x.py --target mock --rounds 10 --analysis-mode strict --language auto --offline
```

### REST POST JSON Target

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --method POST --json-path "reply" \
  --headers '{"Authorization":"Bearer TOKEN","Content-Type":"application/json"}' \
  --language auto --analysis-mode strict --audit --rounds 20 \
  --workers 2 --rate-limit 1 --burst 1 \
  --format html --output reports/rest-final.html \
  --offline --authorized
```

### REST GET Target

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat?q=" \
  --method GET --json-path "data.answer" \
  --language auto --analysis-mode balanced --rounds 10 \
  --workers 1 --rate-limit 1 --offline --authorized
```

### Form-Encoded Target

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --method POST --form --json-path "reply" \
  --headers '{"Authorization":"Bearer TOKEN"}' \
  --language auto --analysis-mode strict --audit \
  --rounds 20 --workers 1 --rate-limit 1 \
  --format html --output reports/form-final.html \
  --offline --authorized
```

### GraphQL Target

```bash
python forge_x.py --target graphql --endpoint "https://api.example.com/graphql" \
  --category graphql --language auto --analysis-mode strict \
  --rounds 20 --workers 2 --rate-limit 1 \
  --format html --output reports/graphql-final.html \
  --offline --authorized
```

Use `--graphql-introspect` only when introspection testing is explicitly allowed by the program or owner.

### WebSocket Target

```bash
python forge_x.py --target custom --method WS --endpoint "wss://chat.example.com/ws" \
  --language auto --analysis-mode strict --rounds 15 \
  --workers 1 --rate-limit 1 \
  --format html --output reports/ws-final.html \
  --offline --authorized
```

### Server-Sent Events Target

```bash
python forge_x.py --target custom --method SSE --endpoint "https://chat.example.com/events" \
  --language auto --analysis-mode strict --rounds 10 \
  --workers 1 --rate-limit 1 \
  --format html --output reports/sse-final.html \
  --offline --authorized
```

### Ollama Local Model

```bash
python forge_x.py --target ollama --model llama3 \
  --category advanced --language auto --analysis-mode balanced \
  --rounds 20 --offline
```

### OpenAI-Compatible Vendor Target

```bash
python forge_x.py --target openai --api-key "$OPENAI_API_KEY" --model "gpt-4o-mini" \
  --language auto --analysis-mode strict --rounds 10 \
  --format json --output reports/openai-check.json --authorized
```

Prefer environment variables or a local secret manager for API keys.

## Analyzer Modes

| Mode | Use case | Behavior |
|------|----------|----------|
| `strict` | Final reports, bug bounty validation, client-facing output | Requires stronger evidence and minimizes false positives. |
| `balanced` | Normal internal testing | Balances precision and recall. |
| `sensitive` | Early exploration and candidate discovery | More sensitive to possible findings; requires manual review. |

Recommended workflow:

```text
sensitive -> candidate discovery
strict    -> retest and validation
manual    -> final reproduction and impact review
```

## Language Modes

| Mode | Description |
|------|-------------|
| `auto` | Uses automatic language handling and mixed payload coverage where appropriate. Recommended default. |
| `en` | English payloads and English-oriented refusal handling. |
| `id` | Bahasa Indonesia payloads and Indonesian refusal handling. |
| `mixed` | Combines English and Indonesian coverage. Useful for bilingual targets. |

Examples:

```bash
python forge_x.py --target mock --language id --analysis-mode strict --offline
python forge_x.py --target mock --language en --analysis-mode strict --offline
python forge_x.py --target mock --language mixed --analysis-mode balanced --offline
```

## Rate Limiting

`--rate-limit` enables a global token-bucket limiter shared by all worker threads.

Examples:

```bash
--rate-limit 1 --burst 1
--rate-limit 0.5 --burst 1
--rate-limit 2 --burst 2
--rate-limit 0
```

Guidance:

| Target type | Suggested workers | Suggested rate limit |
|-------------|-------------------|----------------------|
| Mock/lab | 2-8 | disabled or 5 req/s |
| Small internal app | 1-2 | 0.5-1 req/s |
| Bug bounty target | 1-2 | 0.5-1 req/s unless rules allow more |
| WebSocket/SSE | 1 | 0.5-1 req/s |

For real targets, start slow. Increase only when explicitly allowed.

## Transport Retry and Rate-Limit Safety

Built-in HTTP connectors use one shared retry contract. Retryable transport failures (`408`, `425`, `429`, `500`, `502`, `503`, `504`, connection failures, and timeouts) are retried with bounded exponential backoff; `Retry-After` is honored up to 60 seconds. Every retry passes through the same global rate limiter.

Terminal transport errors are marked as `transport_error`, never passed to the analyzer, and never used to change adaptive payload weights. To prevent a campaign from amplifying provider throttling, a campaign-local circuit breaker stops new target calls after three consecutive exhausted `429` outcomes.

## Report Redaction

Reports are redacted by default. Redaction applies to response bodies, leaked-data fields, evidence previews, and every concrete value extracted by the analyzer. Runtime SQLite result storage uses the same redaction policy by default, so a report is not the only protected output.

Default behavior:

```bash
python forge_x.py --target mock --format html --output reports/report.html
```

Disable redaction only when necessary:

```bash
python forge_x.py --target mock --format json --output reports/raw.json --no-redact
```

Recommended practice:

- Keep `--redact` enabled for shared reports.
- Use `--no-redact` only in restricted internal storage.
- Never commit reports to GitHub.
- Verify redacted evidence before sending a report externally.

## Output Formats

| Format | Use case |
|--------|----------|
| `json` | Machine-readable output and later processing. |
| `html` | Human-readable review report. Recommended for final review. |
| `csv` | Spreadsheet-friendly summary. |
| `pdf` | Static report sharing. |
| `xlsx` | Spreadsheet report with richer formatting. |
| `term` | Terminal-only output. |

Examples:

```bash
python forge_x.py --target mock --format json --output reports/result.json --offline
python forge_x.py --target mock --format html --output reports/result.html --offline
python forge_x.py --target mock --format csv --output reports/result.csv --offline
python forge_x.py --target mock --format pdf --output reports/result.pdf --offline
python forge_x.py --target mock --format xlsx --output reports/result.xlsx --offline
```

## Analyzer and Evidence Model

The analyzer is evidence-gated. A response is not marked as successful just because it contains words like:

```text
password
token
secret
system prompt
you are
kata sandi
rahasia
```

A positive finding requires stronger signals such as:

- Sensitive value assignment.
- Credential-like token/API key format.
- Non-redacted system or developer prompt disclosure.
- Instruction override confirmation.
- Canary response from an injection-style prompt.
- Optional LLM judge confirmation plus local evidence.

False-positive filters include:

- Refusal messages that mention sensitive words.
- Redacted or masked values.
- Placeholder values.
- Educational examples.
- User-supplied values echoed back by the target.

Example analysis metadata:

```json
{
  "success": true,
  "confidence": 0.98,
  "method": "evidence:strong_leak",
  "leak_category": "API Key / Token",
  "severity": "Critical",
  "analysis_mode": "balanced",
  "decision_reason": "Concrete evidence matched for API Key / Token.",
  "evidence": [
    {
      "category": "API Key / Token",
      "source": "labeled-sensitive-assignment",
      "reason": "API key assignment",
      "value_preview": "sk-m...[REDACTED]...4321"
    }
  ]
}
```

## Validation Dataset

The bundled regression dataset contains 171 labeled cases across these case types:

- `api_key_leak`
- `token_leak`
- `password_leak`
- `system_prompt_leak`
- `instruction_override`
- `refusal`
- `redacted`
- `placeholder`
- `educational_example`
- `benign_echo`
- `benign_security_advice`
- `mixed_language_refusal`

Run validation:

```bash
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
```

This dataset is intended to prevent known regressions. It is not a substitute for manual review on real targets.

## GitHub Actions CI

This release includes:

```text
.github/workflows/ci.yml
```

CI runs on push and pull request. It performs:

```text
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
```

If CI fails:

1. Open the failed job in the Actions tab.
2. Read the failing step.
3. Reproduce the same command locally.
4. Fix the code or test.
5. Push again.

## Project Structure

```text
InjectionForgeProX/
|-- forge_x.py
|-- evaluate.py
|-- pyproject.toml
|-- requirements.txt
|-- README.md
|-- SECURITY.md
|-- CHANGELOG.md
|-- docs/
|   |-- PRODUCTION.md
|   |-- USAGE.md
|-- examples/
|   |-- profiles/
|       |-- mock-strict.json
|       |-- rest-balanced.json
|-- core/
|   |-- analyzer.py
|   |-- attack_tree.py
|   |-- adaptive_agent.py
|   |-- config.py
|   |-- database.py
|   |-- engine.py
|   |-- language.py
|   |-- rate_limiter.py
|   |-- redaction.py
|   |-- reporter.py
|   |-- payloads.py
|   |-- payload_generator.py
|   |-- connectors/
|       |-- rest.py
|       |-- graphql.py
|       |-- websocket.py
|       |-- sse.py
|       |-- mock_target.py
|-- data/
|   |-- benchmark.json
|   |-- labeled_test_set.json
|   |-- payloads_basic.json
|   |-- payloads_basic_id.json
|   |-- refusal_phrases.txt
|   |-- refusal_phrases_id.txt
|-- tests/
|-- .github/
|   |-- workflows/
|       |-- ci.yml
```

## Operational Guidance

### For Internal Security Teams

Use profiles for each environment:

```text
examples/profiles/dev-chatbot.json
examples/profiles/staging-chatbot.json
examples/profiles/prod-chatbot-strict.json
```

Recommended defaults:

```text
analysis-mode: strict
language: auto
workers: 1 or 2
rate-limit: 1
redact: true
format: html
```

### For Developers

Run the mock target and validation dataset before modifying analyzer logic:

```bash
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
```

If you change analyzer logic, add regression cases under `data/labeled_test_set.json` and tests under `tests/`.

### For Bug Bounty Testing

Before testing:

- Confirm the target program explicitly allows chatbot/AI testing.
- Confirm rate-limit rules.
- Avoid WAF bypass unless it is explicitly allowed.
- Keep `--analysis-mode strict` for final reports.
- Manually reproduce every finding.

Recommended final retest command:

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode strict \
  --audit --rounds 20 --workers 1 --rate-limit 1 --burst 1 \
  --timeout 25 --diff --format html --output reports/final.html \
  --offline --authorized
```

## Troubleshooting

### `ModuleNotFoundError`

Install dependencies:

```bash
pip install -r requirements.txt
```

For development:

```bash
pip install -e .[test]
```

### `pytest` is not found

Install test dependencies:

```bash
pip install -r requirements.txt
```

### Report folder is missing

The `reports/` directory is created automatically when a report is written:

```bash
python forge_x.py --target mock --format html --output reports/test.html --offline
```

Do not commit generated reports.

### Response text is empty

Check `--json-path`. For example, if the response is:

```json
{
  "data": {
    "reply": "hello"
  }
}
```

Use:

```bash
--json-path "data.reply"
```

### Too many false positives

Use strict mode:

```bash
--analysis-mode strict
```

Also check whether the target is echoing user input. Echoes are usually not vulnerabilities unless they cause a real policy bypass or sensitive disclosure.

### Too many false negatives

Use sensitive mode for discovery:

```bash
--analysis-mode sensitive
```

Then retest candidates with strict mode.

### Real target is slow or unstable

Lower workers and rate limit:

```bash
--workers 1 --rate-limit 0.5 --burst 1 --timeout 30
```

### GitHub Actions shows pending

Open the Actions tab and wait for the workflow to complete. First-time workflow runs can take a few minutes.

### Git push fails because of workflow scope

If pushing `.github/workflows/ci.yml` fails, update your GitHub Personal Access Token with:

```text
repo
workflow
```

Then remove the old GitHub credential from Windows Credential Manager and push again.

## Limitations

No analyzer can guarantee zero false positives or zero false negatives across every real-world LLM response. This project reduces risk through:

- Evidence-gated detection.
- Regression datasets.
- Analyzer modes.
- Redaction.
- Rate limiting.
- CI tests.
- Manual review workflow.

For final reporting, use `--analysis-mode strict` and manually verify every `success=true` finding.

## Security and Reporting

If you discover a vulnerability in this project, follow the guidance in [SECURITY.md](SECURITY.md).

Do not open public issues containing secrets, tokens, private target details, or live exploit evidence.

## Contributing

Before opening a pull request:

```bash
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
```

Recommended contribution areas:

- More labeled regression cases.
- Additional language packs.
- Safer report templates.
- Connector improvements.
- Documentation examples.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
