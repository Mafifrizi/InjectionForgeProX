# Changelog

## 1.1.5 - Dependency Constraint and Supply-Chain Hygiene

- Added bounded compatible version ranges to every direct runtime, test, browser-extra, and build dependency in `pyproject.toml` and `requirements.txt`.
- Removed unused direct dependencies (`numpy`, `httpx`, `openai`, and `playwright`) from the default install surface; provider connectors use the existing HTTP transport layer.
- Added explicit optional browser dependencies for the existing headless WAF workflow.
- Added regression checks that reject unbounded direct dependency declarations and keep `requirements.txt` aligned with package metadata.

## 1.1.4 - Unified Transport Retry and Rate-Limit Integrity

- Replaced connector-level `ERROR: ...` sentinel returns with a raised, typed transport-error contract so HTTP 429, connection failures, and timeouts reach one shared retry boundary.
- Added bounded retry handling for 408, 425, 429, 500, 502, 503, 504, timeouts, and connection failures; non-retryable 4xx responses fail once.
- Added capped `Retry-After` handling, exponential backoff with jitter, per-attempt rate-limiter enforcement, and no final-attempt sleep.
- Ensured transport failures are never sent to the analyzer, report finding logic, or adaptive payload-weight learning.
- Added a per-campaign circuit breaker that stops new target calls after three consecutive exhausted HTTP 429 outcomes.
- Applied the shared transport boundary to normal campaigns, attack-tree, adaptive agent, AI-generated probe flow, and the legacy execution helper.
- Made REST auth/CSRF bootstrap fail closed instead of silently continuing unauthenticated.
- Added transport-contract regression coverage for retries, Retry-After, rate limiting, circuit resets, connector error contracts, analyzer isolation, and actual REST 429 recovery.

## 1.1.3 - Privacy and Operational Safety Hardening

- Added analyzer and redaction coverage for labeled Indonesian/English PII: NIK/KTP, NPWP, phone, email, payment card, bank account, date of birth, address, and customer name.
- Added fallback masking for GitHub, Google, Hugging Face, Slack, JWT, canary/flag, system-prompt, and sensitive URL query values.
- Made reporter APIs redact results by default, including direct library use.
- Sanitized connector error paths and CLI operational output before it reaches logs or reports.
- Disabled automatic target profiling by default; it is now explicit opt-in.


## 1.1.2 - Security and Release Hardening

- Hardened redaction boundaries across SQLite target metadata, local-model profiling, and adaptive-probe retention.
- Fixed evidence-gated attack-tree findings and applied campaign retry/rate-limiting to attack-tree sends.
- Fixed SSE completion handling, WebSocket authentication options, and redaction-safe connector logging.
- Added CSV/XLSX formula-injection protections and report output-directory creation for PDF/XLSX.
- Made GraphQL introspection opt-in during profiling and applied the shared limiter to profiler traffic.
- Made Python wheel packaging deterministic, shipped runtime data files, and moved installed runtime databases to a user-writable directory.


## 1.1.1

- Fixed evidence-driven redaction for natural-language disclosures such as `password is VALUE`, `kata sandi adalah VALUE`, and `token yaitu VALUE`.
- Applied the same redaction policy to runtime SQLite result storage by default.
- Fixed JSON/YAML profile precedence so explicitly supplied CLI flags win even when their value matches an argparse default.
- Wired `--method SSE` to `SSEConnector` and added SSL verification handling for SSE and GraphQL connectors.
- Redacted sensitive request headers, payload snippets, and response snippets in REST connector logs.
- Upgraded local AI probe generation with target fingerprints, deduplicated evidence-gated retention, safe fallback probes, and `--ai-only` support.
- Added regression tests for report redaction, database persistence, profile precedence, streaming connectors, and adaptive probe retention.

## 1.1.0

- Added profile-based configuration through JSON/YAML files.
- Added global token-bucket rate limiter shared across workers.
- Added default report redaction for sensitive-looking values.
- Added CI workflow for compile, tests, analyzer validation, and benchmark evaluation.
- Added production usage documentation and example profiles.
- Added packaging metadata through `pyproject.toml`.
- Expanded regression coverage for production-readiness features.

## 1.0.0

- Initial public framework release.
