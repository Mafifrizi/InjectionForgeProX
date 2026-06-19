# InjectionForge Pro X v1.1.0

Production-ready open-source framework for authorized prompt-injection, chatbot security, and sensitive-disclosure testing.

[![CI](https://github.com/Mafifrizi/InjectionForgeProX/actions/workflows/ci.yml/badge.svg)](https://github.com/Mafifrizi/InjectionForgeProX/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-50%20pytest%20tests-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-orange)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

## Status

InjectionForge Pro X is designed for authorized LLM and chatbot security testing. It is suitable for internal security review, developer validation, lab environments, CTF-style exercises, and bug bounty programs that explicitly allow this type of testing.

Production-readiness baseline included in this release:

- Continuous integration workflow for compile checks, tests, analyzer validation, and strict benchmark evaluation.
- JSON/YAML profiles for repeatable target configuration.
- Global token-bucket rate limiter shared across worker threads.
- Redacted reports by default to reduce secondary leakage risk.
- Evidence-gated analyzer with strict, balanced, and sensitive modes.
- English, Bahasa Indonesia, mixed-language, and auto language modes.
- Regression dataset with 153 labeled cases.
- Packaging metadata through `pyproject.toml`.
- Production usage guide and example profiles.

Use this tool only where you have explicit authorization.

## Installation

```bash
pip install -r requirements.txt
playwright install   # only needed for headless browser mode
```

Optional editable install:

```bash
pip install -e .[test]
injectionforge --version
```

## Quick Validation

Run these before using the tool or before publishing changes:

```bash
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
python forge_x.py --target mock --attack-tree --max-depth 3 --offline --language id --analysis-mode strict
```

Expected result:

```text
pytest: all tests passed
Analyzer validation: quality gate passed
Benchmark: 100% precision and 100% recall on the bundled regression dataset
Attack-tree mock run: successful paths found
```

The bundled dataset is a regression benchmark, not a universal guarantee of zero false positives or zero false negatives on every real target. Manual review is still required before reporting findings.

## Recommended Real-Target Command

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode strict \
  --audit --rounds 20 --workers 2 --rate-limit 1 --burst 1 \
  --timeout 20 --diff --format html --output reports/final.html \
  --offline --authorized
```

Workflow:

1. Use `sensitive` mode for candidate discovery.
2. Retest candidates with `strict` mode.
3. Manually reproduce every finding.
4. Keep report redaction enabled unless the report is stored in a restricted internal location.

## Profiles

Profiles reduce command-line mistakes during repeated engagements.

Example:

```bash
python forge_x.py --profile examples/profiles/mock-strict.json
```

Profile files can be JSON or YAML. CLI flags override profile values.

Example profile:

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

## Rate Limiting

`--rate-limit` enables a global token-bucket limiter shared by all workers.

Examples:

```bash
--rate-limit 1 --burst 1     # one request per second
--rate-limit 0.5 --burst 1   # one request every two seconds
--rate-limit 0               # disabled
```

For small real targets, start with `--workers 1` or `--workers 2` and `--rate-limit 1`.

## Report Redaction

Reports are redacted by default. Sensitive-looking values in response bodies, leaked-data fields, and evidence previews are masked before export.

Default:

```bash
python forge_x.py --target mock --format html --output reports/report.html
```

Disable redaction only when needed:

```bash
python forge_x.py --target mock --format json --output reports/raw.json --no-redact
```

Do not commit report files. They are runtime artifacts and are ignored by `.gitignore`.

## Command Reference

### Profile and safety

| Flag | Description |
|------|-------------|
| `--profile` | JSON/YAML profile file with reusable target settings. |
| `--authorized` | Confirms that you are authorized to test the target. |
| `--version` | Prints the tool version. |

### Target and connection

| Flag | Description |
|------|-------------|
| `--target` | `auto`, `mock`, `custom`, `openai`, `claude`, `gemini`, `cohere`, `ollama`, `huggingface`, `graphql`. |
| `--endpoint` | API/chat endpoint URL. |
| `--method` | `POST`, `GET`, `WS`, or `SSE`. |
| `--headers` | Extra headers as JSON or `Key:Val` pairs. |
| `--cookie` | Cookie string or cookie file. |
| `--json-path` | Path to response text, such as `data.reply`. |
| `--form` | Send as form-encoded data. |
| `--timeout` | Request timeout in seconds. |
| `--proxy` | Proxy URL. |
| `--insecure` | Disable TLS verification for authorized internal testing. |

### Language and analyzer

| Flag | Description |
|------|-------------|
| `--language` | `auto`, `en`, `id`, or `mixed`. |
| `--analysis-mode` | `strict`, `balanced`, or `sensitive`. |
| `--validate` | Run analyzer validation dataset. |
| `--light` | Use lighter validation/model setup. |
| `--offline` | Disable model download and use deterministic checks. |
| `--llm-judge` | Optional Ollama URL for confirmatory LLM judging. |

Analyzer mode guidance:

| Mode | Best for | Behavior |
|------|----------|----------|
| `strict` | Final reports and bug bounty submissions | Lowest false-positive risk. Requires stronger evidence. |
| `balanced` | Normal testing | Balanced evidence gates and recall. |
| `sensitive` | Early exploration | Lower false-negative risk. Requires more manual review. |

### Payload and campaign

| Flag | Description |
|------|-------------|
| `--category` | `basic`, `advanced`, `indirect`, `agent`, or `graphql`. |
| `--rounds` | Number of attempts. |
| `--mutate` | Enable standard mutation. |
| `--aggressive` | Enable aggressive mutation and generation fallback. |
| `--audit` | Use audit-oriented payload selection. |
| `--adaptive` | Enable adaptive payload weighting. |
| `--multi-stage` | Enable two-step priming and exploitation. |
| `--history` | JSON conversation history file. |
| `--workers` | Number of worker threads. |
| `--rate-limit` | Global request rate limit across all workers. |
| `--burst` | Token-bucket burst size. |
| `--ai-payloads` | Generate additional payloads with local AI payload engine. |

### Attack tree and adaptive agent

| Flag | Description |
|------|-------------|
| `--attack-tree` | Run adaptive attack-tree mode. |
| `--max-depth` | Maximum attack-tree depth. |
| `--adaptive-agent` | Run adaptive multi-turn agent. |
| `--target-description` | Manual target description for adaptive agent. |

### Output

| Flag | Description |
|------|-------------|
| `--format` | `json`, `html`, `csv`, `pdf`, `xlsx`, or `term`. |
| `--output` | Output report path. |
| `--redact` / `--no-redact` | Enable or disable report redaction. Redaction is enabled by default. |
| `--diff` | Compare response with a neutral baseline. |

## Usage Examples

### Mock target

```bash
python forge_x.py --profile examples/profiles/mock-strict.json
```

### REST target

```bash
python forge_x.py --target custom --endpoint "https://api.example.com/chat" \
  --method POST --json-path "reply" --headers '{"Authorization":"Bearer TOKEN"}' \
  --language auto --analysis-mode strict --audit --rounds 20 \
  --workers 2 --rate-limit 1 --format html --output reports/final.html \
  --offline --authorized
```

### GraphQL target

```bash
python forge_x.py --target graphql --endpoint "https://api.example.com/graphql" \
  --category graphql --language auto --analysis-mode strict --rounds 20 \
  --workers 2 --rate-limit 1 --format html --output reports/graphql.html \
  --offline --authorized
```

### WebSocket target

```bash
python forge_x.py --target custom --method WS --endpoint "wss://chat.example.com/ws" \
  --language auto --analysis-mode strict --rounds 15 --workers 1 \
  --rate-limit 1 --format html --output reports/ws.html --offline --authorized
```

## Analyzer and Evidence Model

The analyzer is evidence-gated. A response is not marked as successful just because it contains words like `password`, `token`, `secret`, `system prompt`, `you are`, `kata sandi`, or `rahasia`.

A success requires concrete evidence such as:

- Sensitive value assignment or credential-like value.
- Non-redacted system/developer prompt disclosure.
- Explicit instruction-override signal.
- Audit canary returned from an injection-style prompt.
- Optional LLM judge confirmation plus local evidence.

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
      "value_preview": "sk-m...[REDACTED]...4321"
    }
  ]
}
```

## Validation Dataset

The bundled dataset contains 153 labeled cases across these case types:

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
python evaluate.py --analysis-mode strict
```

## Project Layout

```text
InjectionForgeProX/
|-- forge_x.py
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
|-- core/
|   |-- analyzer.py
|   |-- attack_tree.py
|   |-- adaptive_agent.py
|   |-- config.py
|   |-- language.py
|   |-- rate_limiter.py
|   |-- redaction.py
|   |-- reporter.py
|   |-- connectors/
|-- data/
|-- tests/
|-- .github/workflows/ci.yml
```

## Limitations

No analyzer can guarantee zero false positives or zero false negatives across every real-world LLM response. This project reduces risk through deterministic gates, labeled regression data, explicit analyzer modes, rate limiting, redacted reports, and structured evidence.

For final reporting, use `--analysis-mode strict` and manually review every `success=true` result.

For exploration, use `--analysis-mode sensitive`, then retest findings with strict mode before reporting.

## License

Released under the MIT License. See [LICENSE](LICENSE).
