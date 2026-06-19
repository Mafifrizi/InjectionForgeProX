# InjectionForge Pro X v1.0

Advanced framework for authorized prompt-injection, chatbot security, and sensitive-disclosure testing.

[![Tests](https://img.shields.io/badge/tests-45%20pytest%20tests-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

## Overview

InjectionForge Pro X is a command-line security testing framework for evaluating whether an AI assistant, chatbot, or LLM-backed API leaks sensitive information or accepts unsafe instruction overrides.

The tool is designed for authorized testing only. It is suitable for internal security review, lab validation, CTF-style exercises, and bug bounty testing where the target program explicitly allows this class of testing.

Core goals:

- Keep offline mode lightweight and deterministic.
- Support English, Bahasa Indonesia, and mixed-language targets.
- Reduce false positives with evidence-gated analysis.
- Reduce false negatives with configurable detection modes.
- Produce reports that are readable by security engineers and developers.

## Key Features

- Multi-protocol connectors: REST, WebSocket, Server-Sent Events, GraphQL, Ollama, OpenAI, Claude, Gemini, Cohere, and Hugging Face.
- Multilingual payload support: English, Bahasa Indonesia, mixed, and auto mode.
- Evidence-gated analyzer: a finding requires concrete evidence, not just a broad keyword match.
- Analyzer modes:
  - `strict`: conservative mode for reporting, prioritizes low false positives.
  - `balanced`: default mode, balanced precision and recall.
  - `sensitive`: exploration mode, prioritizes lower false negatives.
- Structured evidence in reports: decision reason, evidence source, leak category, severity, language, and analysis mode.
- Attack-tree mode for multi-turn probing.
- Adaptive agent mode with target profiling and optional local LLM payload generation.
- WAF and stealth options: cloudscraper, curl_cffi, TLS fingerprint selection, headless browser support, proxy, and delay controls.
- Multi-format reports: JSON, HTML, CSV, PDF, XLSX, and terminal summary.
- SQLite result logging.
- Regression tests for multilingual analysis and FP/FN hardening.

## Installation

```bash
pip install -r requirements.txt
playwright install   # only needed for headless browser mode
```

## Quick Validation

Run these checks before using the tool against any authorized target:

```bash
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline
python evaluate.py
```

Expected high-level result:

```text
pytest: all tests passed
Analyzer validation: quality gate passed
Benchmark: 100% precision, 100% recall on the included labeled dataset
```

The bundled dataset is a regression benchmark, not a guarantee of zero false positives or zero false negatives on all real-world targets. Real engagements still require manual review.

## Command Reference

### Target and Connection

| Flag | Description | Example |
|------|-------------|---------|
| `--target` | Target type: `auto`, `mock`, `custom`, `openai`, `claude`, `gemini`, `cohere`, `ollama`, `huggingface`, `graphql` | `--target custom` |
| `--endpoint` | API/chat endpoint URL | `--endpoint https://api.example.com/chat` |
| `--method` | Method: `POST`, `GET`, `WS`, `SSE` | `--method POST` |
| `--headers` | Extra headers as JSON or `Key:Val` pairs | `--headers '{"Authorization":"Bearer token"}'` |
| `--cookie` | Cookie string or cookie file | `--cookie "session=abc123"` |
| `--json-path` | Response text path | `--json-path "data.reply"` |
| `--form` | Send request as form-encoded data | `--form` |
| `--timeout` | Request timeout in seconds | `--timeout 30` |
| `--proxy` | Proxy URL | `--proxy http://127.0.0.1:8080` |
| `--insecure` | Disable TLS verification for internal testing | `--insecure` |

### Language and Analyzer

| Flag | Description | Example |
|------|-------------|---------|
| `--language` | Payload/analyzer language: `auto`, `en`, `id`, `mixed` | `--language auto` |
| `--analysis-mode` | Detection mode: `strict`, `balanced`, `sensitive` | `--analysis-mode strict` |
| `--validate` | Run analyzer validation dataset | `--validate` |
| `--light` | Use a lighter validation/model setup | `--light` |
| `--offline` | Disable model download and use deterministic local checks | `--offline` |
| `--llm-judge` | Optional Ollama URL for confirmatory LLM judging | `--llm-judge http://localhost:11434` |

Analyzer mode guidance:

| Mode | Best for | Behavior |
|------|----------|----------|
| `strict` | Final reports and bug bounty submissions | Minimizes false positives. Requires stronger evidence. |
| `balanced` | Default testing | Balanced evidence gates and recall. |
| `sensitive` | Early exploration | Reduces false negatives, but findings need more manual review. |

### Payload and Campaign

| Flag | Description | Example |
|------|-------------|---------|
| `--category` | Payload category: `basic`, `advanced`, `indirect`, `agent`, `graphql` | `--category advanced` |
| `--rounds` | Number of attempts | `--rounds 20` |
| `--mutate` | Enable standard mutation | `--mutate` |
| `--aggressive` | Enable aggressive mutation and generation fallback | `--aggressive` |
| `--audit` | Use audit-oriented payload selection | `--audit` |
| `--adaptive` | Enable adaptive payload weighting | `--adaptive` |
| `--multi-stage` | Enable two-step priming and exploitation | `--multi-stage` |
| `--history` | JSON conversation history file | `--history convo.json` |
| `--workers` | Number of worker threads | `--workers 8` |
| `--ai-payloads` | Generate additional payloads with local AI payload engine | `--ai-payloads` |

### Attack Tree and Adaptive Agent

| Flag | Description | Example |
|------|-------------|---------|
| `--attack-tree` | Run adaptive attack-tree mode | `--attack-tree` |
| `--max-depth` | Maximum attack-tree depth | `--max-depth 3` |
| `--adaptive-agent` | Run adaptive multi-turn agent | `--adaptive-agent` |
| `--target-description` | Manual target description for adaptive agent | `--target-description "support chatbot"` |

### WAF, Stealth, and Discovery

| Flag | Description | Example |
|------|-------------|---------|
| `--bypass-waf` | WAF bypass profile: `cloudflare`, `akamai`, `auto`, `none` | `--bypass-waf auto` |
| `--tls-fingerprint` | TLS profile: `random`, `chrome`, `firefox`, `safari` | `--tls-fingerprint chrome` |
| `--headless` | Use headless browser for JavaScript challenge handling | `--headless` |
| `--stealth` | Random User-Agent and delay jitter | `--stealth` |
| `--delay` | Base delay between requests | `--delay 1.5` |
| `--discover` | Discover chat endpoint from a webpage | `--discover` |
| `--auto-profile` | Profile target and choose strategy automatically | `--auto-profile` |
| `--waf-detect` | Detect WAF and exit | `--waf-detect` |
| `--graphql-introspect` | Introspect GraphQL schema before testing | `--graphql-introspect` |

### Output

| Flag | Description | Example |
|------|-------------|---------|
| `--format` | Report format: `json`, `html`, `csv`, `pdf`, `xlsx`, `term` | `--format html` |
| `--output` | Output report path | `--output reports/client-a.html` |
| `--diff` | Compare response with a neutral baseline | `--diff` |

## Usage Examples

### Mock target validation

```bash
python forge_x.py --target mock --rounds 10 --aggressive --format json --offline
```

### Bahasa Indonesia mode

```bash
python forge_x.py --target mock --attack-tree --max-depth 3 --language id --offline
```

### Auto multilingual mode

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --method POST --json-path "reply" --language auto --rounds 20 --offline
```

### Strict report mode

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --json-path "reply" --analysis-mode strict --format html --output reports/final.html --offline
```

### Sensitive exploration mode

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --json-path "reply" --analysis-mode sensitive --rounds 50 --format json --offline
```

### GraphQL target

```bash
python forge_x.py --target graphql --endpoint "https://api.example.com/graphql" \
  --category graphql --rounds 20 --aggressive --format json --offline
```

### WebSocket target

```bash
python forge_x.py --target custom --method WS --endpoint "wss://chat.example.com/ws" \
  --rounds 10 --aggressive --format json --offline
```

## Analyzer and Evidence Model

The analyzer is intentionally evidence-gated. A response is not marked as successful just because it contains broad words like `password`, `token`, `secret`, `system prompt`, `you are`, `kata sandi`, or `rahasia`.

A success requires one of the following:

- Concrete sensitive value evidence, such as a labeled API key, bearer token, password assignment, internal token assignment, or flag format.
- Valid system/developer prompt label with non-redacted content.
- Explicit instruction-override signal.
- Explicit audit canary returned from an injection-style prompt.
- Optional LLM judge confirmation plus local evidence, except in `sensitive` mode where a low-confidence potential disclosure can be surfaced for manual review.

The analyzer filters common false-positive sources:

- Refusals that mention sensitive terms.
- Redacted or masked values.
- Placeholder values.
- Educational examples.
- User-supplied values echoed back by the target.

Every result includes structured metadata:

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
      "value_preview": "sk-m...4321"
    }
  ]
}
```

## Validation Dataset

The bundled validation files are:

```text
data/labeled_test_set.json
data/benchmark.json
```

The dataset contains 153 labeled cases across these case types:

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

Run:

```bash
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode balanced
python evaluate.py --analysis-mode strict
python evaluate.py --analysis-mode sensitive
```

## Reports

Reports are written to `reports/` by default. The HTML report is designed for security/developer review and includes:

- Status
- Confidence
- Severity
- Leak category
- Analyzer method
- Analyzer mode
- Decision reason
- Evidence summary
- Payload and response excerpts

JSON reports preserve the full result object for later automation.

## Project Layout

```text
InjectionForgeProX/
|-- forge_x.py
|-- requirements.txt
|-- README.md
|-- LICENSE
|-- evaluate.py
|-- core/
|   |-- analyzer.py
|   |-- attack_tree.py
|   |-- adaptive_agent.py
|   |-- language.py
|   |-- llm_generator.py
|   |-- payloads.py
|   |-- payload_generator.py
|   |-- obfuscator.py
|   |-- reporter.py
|   |-- validator.py
|   |-- database.py
|   |-- connectors/
|       |-- rest.py
|       |-- websocket.py
|       |-- sse.py
|       |-- graphql.py
|       |-- mock_target.py
|-- data/
|   |-- payloads_basic.json
|   |-- payloads_advanced.json
|   |-- payloads_indirect.json
|   |-- payloads_agent.json
|   |-- payloads_graphql.json
|   |-- payloads_basic_id.json
|   |-- payloads_advanced_id.json
|   |-- payloads_indirect_id.json
|   |-- payloads_agent_id.json
|   |-- payloads_graphql_id.json
|   |-- refusal_phrases.txt
|   |-- refusal_phrases_id.txt
|   |-- labeled_test_set.json
|   |-- benchmark.json
|-- tests/
|   |-- test_language.py
|   |-- test_analyzer_regression_fp_fn.py
|   |-- tests_analyzer.py
|   |-- tests_payloads.py
|   |-- tests_reporter.py
|   |-- test_rest_connector.py
|   |-- test_integration.py
```

## Limitations

No analyzer can guarantee zero false positives or zero false negatives across every real-world LLM response. This project reduces risk through deterministic gates, labeled regression data, explicit analyzer modes, and structured evidence.

For final bug bounty or client reporting, use `--analysis-mode strict` and manually review each `success=true` result.

For exploration, use `--analysis-mode sensitive`, then retest findings with strict mode before reporting.

## License

Released under the MIT License. See [LICENSE](LICENSE).
