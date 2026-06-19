# Production Readiness Guide

InjectionForge Pro X is intended for authorized LLM/chatbot security testing. This guide defines the operational baseline for using it safely in real engagements.

## Recommended workflow

1. Confirm that the target program explicitly authorizes chatbot, LLM, or prompt-injection testing.
2. Start with a low-noise profile and a global rate limit.
3. Use `sensitive` mode for candidate discovery only.
4. Re-run candidate findings in `strict` mode.
5. Manually reproduce any finding before submitting a report.
6. Keep report redaction enabled unless you are producing a private internal artifact for a restricted audience.

## Real-target baseline

```bash
python forge_x.py --target custom --endpoint "https://target.example/api/chat" \
  --method POST --json-path "reply" --language auto --analysis-mode strict \
  --audit --rounds 20 --workers 2 --rate-limit 1 --burst 1 \
  --timeout 20 --diff --format html --output reports/final.html \
  --offline --authorized
```

## Profiles

Profiles reduce command-line mistakes during repeated engagements.

```bash
python forge_x.py --profile examples/profiles/rest-balanced.json
```

CLI flags override profile values when explicitly set.

## Redaction

Generated reports are redacted by default. Sensitive-looking values in response bodies, evidence previews, and leaked-data fields are masked before export.

Use raw output only when necessary and only in a secure location:

```bash
python forge_x.py --profile examples/profiles/mock-strict.json --no-redact
```

## Rate limiting

`--rate-limit` is a global token bucket shared across worker threads. It limits request rate across the campaign rather than per worker.

Examples:

- `--rate-limit 1 --burst 1`: at most one request per second.
- `--rate-limit 0.5 --burst 1`: one request every two seconds.
- `--rate-limit 0`: disabled.

## Quality gates

Before publishing or releasing changes, run:

```bash
python -m compileall -q .
pytest -q
python forge_x.py --validate --light --offline --analysis-mode balanced
python evaluate.py --analysis-mode strict
python forge_x.py --target mock --attack-tree --max-depth 3 --offline --language id --analysis-mode strict
```

## Files that must not be committed

- `injectionforge_results.db`
- `reports/*`
- `.pytest_cache/`
- `__pycache__/`
- `*.pyc`
- `.env` or credential files
