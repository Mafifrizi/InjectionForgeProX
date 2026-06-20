import argparse
import sys
import os
import json
import concurrent.futures
import logging  # <-- TAMBAHAN
from pathlib import Path

from core.payloads import PayloadManager
from core.analyzer import SmartAnalyzer, normalize_analysis_mode
from core.engine import InjectionEngine
from core.validator import validate_analyzer
from core.redaction import redact_text
from core.reporter import (generate_json_report, generate_html_report,
                           generate_csv_report, generate_pdf_report,
                           generate_xlsx_report, print_colored_summary)
from core.profiler import TargetProfiler
from core.auth import session_login
from core.auto_discovery import discover_endpoint
from core.waf_bypass import WAFBypass, detect_waf
from core.adaptive_agent import AdaptiveAgent
from core.llm_generator import LLMGenerator
from core.database import init_db, save_result
from core.payload_engine import AIPayloadEngine
from core.config import load_profile, apply_profile
from core.rate_limiter import build_rate_limiter
from core.transport import TransportCircuitBreaker, send_with_retry

VERSION = "1.1.5"


def parse_headers(val):
    if not val:
        return {}
    cleaned = val.strip()
    if cleaned.startswith("{") and cleaned.endswith("}"):
        cleaned = cleaned[1:-1].strip()
    try:
        return json.loads(val)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return json.loads("{" + cleaned + "}")
    except (json.JSONDecodeError, ValueError):
        pass
    result = {}
    for pair in cleaned.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            k, v = pair.split(":", 1)
        elif "=" in pair:
            k, v = pair.split("=", 1)
        else:
            continue
        k = k.strip().strip("'\"")
        v = v.strip().strip("'\"")
        result[k] = v
    return result


def parse_auth_data(val):
    if not val:
        return None
    try:
        return json.loads(val)
    except (json.JSONDecodeError, ValueError):
        return {key.strip(): value.strip() for key, value in (item.split("=", 1) for item in val.split(",") if "=" in item)}



def _explicit_cli_fields(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """Return argparse destinations explicitly supplied on the command line.

    Profile precedence cannot be inferred from parsed values because a user can
    intentionally provide a value equal to the parser default (for example,
    ``--rounds 10``). This helper preserves that intent before profile values
    are applied.
    """
    option_to_dest = {
        option: action.dest
        for action in parser._actions
        for option in action.option_strings
    }
    explicit: set[str] = set()
    for token in argv:
        if token == "--":
            break
        option = token.split("=", 1)[0] if token.startswith("-") else ""
        destination = option_to_dest.get(option)
        if destination:
            explicit.add(destination)
    return explicit


def _derived_target_description(args) -> str:
    """Build a non-secret description for adaptive local generation."""
    if args.target_description:
        return redact_text(args.target_description)
    endpoint = redact_text(args.endpoint or "local/default endpoint")
    return (
        f"authorized {args.target} chatbot assessment; method={args.method}; "
        f"endpoint={endpoint}; language={args.language}; category={args.category}"
    )

def main():
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=f"InjectionForge Pro X v{VERSION} - Production Ready",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Contoh penggunaan:
  # Validasi analyzer
  python forge_x.py --validate --light --offline

  # Mock target (latihan)
  python forge_x.py --target mock --rounds 10 --aggressive --format json --offline

  # Model lokal (Ollama)
  python forge_x.py --target ollama --model llama3 --category advanced --rounds 20 --aggressive --format json --offline

  # REST API dengan audit mode
  python forge_x.py --target custom --endpoint "https://api.umkm.com/chat" --method POST --json-path "reply" --audit --rounds 20 --format html --offline

  # WAF bypass
  python forge_x.py --target custom --endpoint "https://protected.umkm.com/api/chat" --bypass-waf auto --tls-fingerprint random --stealth --aggressive --rounds 20

  # Adaptive agent multi-turn dengan auto-profiling
  python forge_x.py --target custom --endpoint "http://127.0.0.1:5000/v1/chat" --adaptive-agent --rounds 10 --headers "X-API-Key:masta-dev-123"

  # AI-generated payloads + multi-threading (menggunakan worker bawaan engine)
  python forge_x.py --target custom --endpoint "https://api.umkm.com/chat" --ai-payloads --workers 4 --rounds 20 --format json
        """
    )

    # Profile and safety
    parser.add_argument("--profile", help="JSON/YAML profile file containing reusable target settings")
    parser.add_argument("--authorized", action="store_true", help="Confirm that you are authorized to test the target")
    parser.add_argument("--version", action="store_true", help="Print version and exit")

    # Target & koneksi
    parser.add_argument("--target", choices=["auto","mock","custom","openai","claude","gemini","cohere","ollama","huggingface","graphql"], default="auto", help="Jenis target (default: auto)")
    parser.add_argument("--method", default="POST", help="HTTP method (POST, GET, WS, SSE)")
    parser.add_argument("--endpoint", help="URL endpoint API/chat")
    parser.add_argument("--api-key", help="API key (untuk vendor LLM)")
    parser.add_argument("--model", help="Nama model (untuk Ollama/Hugging Face)")
    parser.add_argument("--headers", help='Header tambahan. Format: JSON \'{"Key":"Val"}\' atau "Key:Val,Key:Val"')
    parser.add_argument("--cookie", help="Cookie string atau file")
    parser.add_argument("--json-path", help="Jalur ke teks respons (contoh: data.reply)")
    parser.add_argument("--form", action="store_true", help="Kirim sebagai form-urlencoded")
    parser.add_argument("--csrf-token", help="URL untuk ambil CSRF token, atau token statis")
    parser.add_argument("--auth-endpoint", help="URL untuk ambil auth token")
    parser.add_argument("--auth-data", help="Data untuk auth request (JSON atau key=val)")
    parser.add_argument("--login", help="URL form login untuk auto-login")
    parser.add_argument("--username", help="Username untuk login")
    parser.add_argument("--password", help="Password untuk login")
    parser.add_argument("--proxy", help="Proxy URL (contoh: http://127.0.0.1:8080)")
    parser.add_argument("--stealth", action="store_true", help="Aktifkan random User-Agent + delay jitter")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay dasar antar request (detik)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout request (detik)")
    parser.add_argument("--language", choices=["auto","en","id","mixed"], default="auto", help="Bahasa payload/analyzer: auto, en, id, mixed (default: auto)")
    parser.add_argument("--analysis-mode", choices=["strict","balanced","sensitive"], default="balanced", help="Mode deteksi analyzer: strict=minim FP, balanced=default, sensitive=minim FN")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Global request rate limit in requests/second across all workers (0=disabled)")
    parser.add_argument("--burst", type=int, default=1, help="Token bucket burst size for --rate-limit")

    # Payload & serangan
    parser.add_argument("--rounds", type=int, default=10, help="Jumlah percobaan injeksi")
    parser.add_argument("--category", choices=["basic","advanced","indirect","agent","graphql"], default="basic", help="Kategori payload")
    parser.add_argument("--mutate", action="store_true", help="Aktifkan mutasi standar (base64, ROT13, dll.)")
    parser.add_argument("--aggressive", action="store_true", help="Mutasi agresif + generator jika database kosong")
    parser.add_argument("--adaptive", action="store_true", help="Payload adaptif berdasarkan bobot keberhasilan")
    parser.add_argument("--multi-stage", action="store_true", help="Serangan 2-langkah (priming + exploitation)")
    parser.add_argument("--history", help="File JSON conversation history")
    parser.add_argument("--audit", action="store_true", help="Mode audit: payload bisnis tanpa mutasi")
    parser.add_argument("--attack-tree", action="store_true", help="Gunakan attack tree multi-turn adaptif")
    parser.add_argument("--max-depth", type=int, default=2, help="Kedalaman maksimum attack tree")
    parser.add_argument("--workers", type=int, default=4, help="Jumlah thread untuk multi-threading")
    parser.add_argument("--ai-payloads", action="store_true", help="Generate adaptive assessment probes with a local LLM and retain validated successes")
    parser.add_argument("--ai-only", action="store_true", help="Run only AI-generated probes; skip the template baseline campaign")
    parser.add_argument("--ai-generator-url", default="http://localhost:11434", help="Local Ollama URL for --ai-payloads")
    parser.add_argument("--ai-generator-model", default="llama3", help="Local model name for --ai-payloads")
    parser.add_argument("--ai-generator-timeout", type=int, default=8, help="Local AI generation timeout in seconds (default: 8)")

    # Fitur baru: Adaptive Agent & LLM Generator
    parser.add_argument("--adaptive-agent", action="store_true", help="Gunakan adaptive multi-turn agent dengan auto-profiling")
    parser.add_argument("--target-description", help="Deskripsi target opsional. Jika dikosongkan, akan diisi otomatis.")

    # Output
    parser.add_argument("--output", help="File laporan (default: reports/report.json)")
    parser.add_argument("--format", choices=["json","html","csv","pdf","xlsx","term"], default="json", help="Format laporan")
    parser.add_argument("--diff", action="store_true", help="Bandingkan respons dengan baseline (prompt netral)")
    parser.add_argument("--redact", dest="redact", action=argparse.BooleanOptionalAction, default=True, help="Redact sensitive values in generated reports (default: enabled)")

    # Validasi
    parser.add_argument("--validate", action="store_true", help="Self-test analyzer (presisi >= 95%%)")
    parser.add_argument("--light", action="store_true", help="Gunakan hanya satu model (lebih ringan)")
    parser.add_argument("--offline", action="store_true", help="Mode offline: tidak unduh model, hanya regex+refusal")

    # Discovery & profiling
    parser.add_argument("--discover", action="store_true", help="Auto-discovery endpoint dari halaman web")
    parser.add_argument("--discover-external", action="store_true", help="Allow auto-discovery to follow external script/endpoint references")
    parser.add_argument("--auto-profile", action=argparse.BooleanOptionalAction, default=False, help="Enable or disable target profiling (default: disabled)")
    parser.add_argument("--waf-detect", action="store_true", help="Deteksi WAF tanpa menjalankan serangan")
    parser.add_argument("--graphql-introspect", action="store_true", help="Introspect GraphQL schema sebelum serangan")

    # WAF bypass
    parser.add_argument("--bypass-waf", choices=["cloudflare","akamai","auto","none"], default="none", help="Bypass WAF (cloudflare, akamai, auto)")
    parser.add_argument("--tls-fingerprint", choices=["random","chrome","firefox","safari"], default="none", help="TLS fingerprint untuk hindari deteksi")
    parser.add_argument("--headless", action="store_true", help="Gunakan headless browser untuk JS challenge")

    # Keamanan koneksi
    parser.add_argument("--insecure", action="store_true", help="Nonaktifkan verifikasi SSL (hanya untuk testing internal yang sah!)")
    parser.add_argument("--llm-judge", help="URL Ollama untuk LLM judge (contoh: http://localhost:11434)")

    raw_argv = sys.argv[1:]
    args = parser.parse_args(raw_argv)
    explicit_cli_fields = _explicit_cli_fields(parser, raw_argv)

    if args.version:
        print(f"InjectionForge Pro X {VERSION}")
        return

    if args.profile:
        try:
            args = apply_profile(args, load_profile(args.profile), explicit_fields=explicit_cli_fields)
        except Exception as e:
            sys.exit(f"[!] Profile error: {e}")

    if args.target not in ("mock", "ollama") and not args.authorized and not args.validate and not args.waf_detect:
        print("[WARN] Run this tool only against systems you are explicitly authorized to test. Use --authorized to acknowledge scope.")

    rate_limiter = build_rate_limiter(args.rate_limit, args.burst)
    if rate_limiter.enabled:
        print(f"[RateLimit] Global limit: {args.rate_limit} req/s, burst={args.burst}")

    init_db()

    # Validasi analyzer
    if args.validate:
        ok = validate_analyzer(light=args.light, offline=args.offline, language=args.language, analysis_mode=args.analysis_mode)
        sys.exit(0 if ok else 1)

    # WAF detection
    if args.waf_detect:
        if not args.endpoint:
            sys.exit("[!] Butuh --endpoint untuk mendeteksi WAF")
        waf = detect_waf(args.endpoint)
        print(f"[WAF] Terdeteksi: {waf or 'tidak diketahui'}")
        if waf and args.bypass_waf == "none":
            args.bypass_waf = waf
        return

    # Auto-discovery
    if args.discover and args.endpoint:
        print(f"[*] Mencari endpoint dari {redact_text(args.endpoint)}...")
        discovered = discover_endpoint(args.endpoint, insecure=args.insecure, allow_external=args.discover_external)
        if discovered:
            args.endpoint = discovered["endpoint"]
            args.method = discovered.get("method", "POST")
            args.json_path = discovered.get("json_path", None)
            print(f"   Ditemukan: {args.method} {redact_text(args.endpoint)}")
        else:
            print("[!] Gagal menemukan endpoint.")

    # Auto-login
    if args.login:
        creds = {"username": args.username, "password": args.password}
        extra = session_login(args.login, creds, insecure=args.insecure)
        if extra:
            if args.headers:
                h = parse_headers(args.headers)
                h.update(extra)
                args.headers = json.dumps(h)
            else:
                args.headers = json.dumps(extra)
            print("[+] Session berhasil didapat.")
        else:
            print("[!] Login gagal, lanjut tanpa session.")

    # WAF session
    waf_session = None
    if args.bypass_waf != "none":
        waf_session = WAFBypass(
            bypass_type=args.bypass_waf,
            tls_fingerprint=args.tls_fingerprint,
            headless=args.headless,
            proxy=args.proxy,
            insecure=args.insecure
        )

    # Profiling
    if args.auto_profile and args.target in ("auto", "custom", "graphql"):
        profiler = TargetProfiler(
            args.endpoint,
            args.method,
            parse_headers(args.headers),
            insecure=args.insecure,
            rate_limiter=rate_limiter,
            allow_graphql_introspection=args.graphql_introspect,
        )
        profile = profiler.profile
        print(f"[Profile] {profile.get('type')} -> strategi: {profile.get('strategy')}")
        if args.target == "auto":
            if profile.get("payload_cat"):
                args.category = profile["payload_cat"]
            if profile.get("strategy") == "multi_turn":
                args.multi_stage = True
            if profile.get("type") == "graphql" and args.target != "graphql":
                args.target = "graphql"

    # Pilih konektor
    if args.target == "mock":
        from core.connectors.mock_target import MockTargetConnector
        conn = MockTargetConnector()
    elif args.target == "graphql":
        from core.connectors.graphql import GraphQLConnector
        conn = GraphQLConnector(
            endpoint=args.endpoint,
            api_key=args.api_key or "",
            headers=parse_headers(args.headers),
            timeout=args.timeout,
            insecure=args.insecure
        )
    elif args.target in ("openai", "claude", "gemini", "cohere", "ollama", "huggingface"):
        if args.target == "openai":
            key = args.api_key or os.environ.get("OPENAI_API_KEY")
            if not key: sys.exit("[!] OpenAI butuh --api-key")
            from core.connectors.openai import OpenAIConnector
            conn = OpenAIConnector(key)
        elif args.target == "claude":
            key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key: sys.exit("[!] Claude butuh --api-key")
            from core.connectors.claude import ClaudeConnector
            conn = ClaudeConnector(key)
        elif args.target == "gemini":
            key = args.api_key or os.environ.get("GOOGLE_API_KEY")
            if not key: sys.exit("[!] Gemini butuh --api-key")
            from core.connectors.gemini import GeminiConnector
            conn = GeminiConnector(key)
        elif args.target == "cohere":
            key = args.api_key or os.environ.get("COHERE_API_KEY")
            if not key: sys.exit("[!] Cohere butuh --api-key")
            from core.connectors.cohere import CohereConnector
            conn = CohereConnector(key)
        elif args.target == "ollama":
            from core.connectors.ollama import OllamaConnector
            conn = OllamaConnector(
                base_url=args.endpoint or "http://localhost:11434",
                model=args.model or "llama3"
            )
        else:  # huggingface
            key = args.api_key or os.environ.get("HF_TOKEN")
            from core.connectors.huggingface import HuggingFaceConnector
            conn = HuggingFaceConnector(
                endpoint=args.model or "",
                api_key=key
            )
    else:
        method_upper = args.method.upper()
        if method_upper == "WS":
            from core.connectors.websocket import WebSocketConnector
            conn = WebSocketConnector(
                endpoint=args.endpoint,
                timeout=args.timeout,
                headers=parse_headers(args.headers),
                cookie=args.cookie,
                api_key=args.api_key or "",
                verify_ssl=not args.insecure,
                proxy=args.proxy,
            )
        elif method_upper == "SSE":
            from core.connectors.sse import SSEConnector
            sse_headers = parse_headers(args.headers)
            if args.cookie:
                sse_headers.setdefault("Cookie", args.cookie)
            conn = SSEConnector(
                endpoint=args.endpoint,
                api_key=args.api_key or "",
                headers=sse_headers,
                timeout=args.timeout,
                verify_ssl=not args.insecure,
            )
        else:
            from core.connectors.rest import RESTChatbotConnector
            conn = RESTChatbotConnector(
                endpoint=args.endpoint, method=args.method, api_key=args.api_key,
                headers=parse_headers(args.headers), cookie=args.cookie,
                json_path=args.json_path, form_data=args.form,
                csrf_token_url=args.csrf_token, auth_endpoint=args.auth_endpoint,
                auth_data=parse_auth_data(args.auth_data), proxy=args.proxy,
                stealth=args.stealth, delay=args.delay, timeout=args.timeout,
                waf_session=waf_session, verify_ssl=not args.insecure
            )

    try:
        pm = PayloadManager(language=args.language)
    except Exception as e:
        sys.exit(f"[!] Payload error: {e}")

    # Inisialisasi AIPayloadEngine jika diminta
    ai_engine = None
    if args.ai_payloads:
        ai_engine = AIPayloadEngine(
            ollama_url=args.ai_generator_url,
            model=args.ai_generator_model,
            language=args.language,
            timeout=args.ai_generator_timeout,
        )
        print("[*] Adaptive AI probe engine aktif (local model, evidence-gated retention).")

    # =========================================================
    # Adaptive Agent (dengan kemungkinan override generator)
    # =========================================================
    if args.adaptive_agent:
        from core.adaptive_agent import AdaptiveAgent
        from core.llm_generator import LLMGenerator

        llm_gen = LLMGenerator(language=args.language)
        if ai_engine:
            class AIProbeAdapter:
                def __init__(self, engine, language):
                    self.engine = engine
                    self.language = language

                def generate_payloads(self, target_description, strategy="instruction_boundary", n=1):
                    return self.engine.generate(
                        target_description,
                        context=f"strategy={strategy}",
                        n=n,
                        strategy=strategy,
                        language=self.language,
                    )

            llm_gen = AIProbeAdapter(ai_engine, args.language)
            print("[*] Adaptive Agent akan menggunakan adaptive AI probe engine.")

        adaptive_analyzer = SmartAnalyzer(
            pm.refusal,
            use_dual_model=False,
            offline=True,
            llm_judge_url=args.llm_judge or "http://localhost:11434",
            language=args.language,
            analysis_mode=args.analysis_mode
        )
        agent = AdaptiveAgent(conn, adaptive_analyzer, llm_gen=llm_gen, language=args.language, rate_limiter=rate_limiter)

        if not args.target_description:
            print("[*] Auto-profiling target...")
            auto_desc = agent.auto_profile()
            print(f"[*] Profil otomatis: {redact_text(auto_desc[:100])}...")
        else:
            agent.target_description = args.target_description
            print(f"[*] Menggunakan deskripsi manual: {redact_text(args.target_description)}")

        print(f"[*] Adaptive Agent aktif. Target: {redact_text(agent.target_description)}")
        results = agent.run_adaptive_session(max_turns=args.rounds)

        success = sum(1 for r in results if r["success"])
        total = len(results)
        print(f"\n[Summary] {success}/{total} sukses ({(success/total)*100:.1f}%)" if total else "\n[Summary] No results")

        if ai_engine:
            for r in results:
                if r["success"]:
                    ai_engine.record_success(
                        target_description=agent.target_description or _derived_target_description(args),
                        payload=r["payload"],
                        leak_category=r.get("leak_category", "unknown"),
                        severity=r.get("severity", "Medium")
                    )

        for i, r in enumerate(results, 1):
            status = "SUCCESS" if r["success"] else "FAIL"
            cat = r.get("leak_category", "")
            sev = r.get("severity", "Info")
            print(f"  Turn {i} [{r['strategy']}]: {redact_text(r['payload'][:80])}... -> {status} {cat}/{sev}")

        out = args.output or f"reports/adaptive_report.{args.format if args.format != 'term' else 'json'}"
        if args.format == "json":
            generate_json_report(results, out, redact=args.redact)
        elif args.format == "html":
            generate_html_report(results, out, redact=args.redact)
        elif args.format == "csv":
            generate_csv_report(results, out, redact=args.redact)
        elif args.format == "pdf":
            generate_pdf_report(results, out, redact=args.redact)
        elif args.format == "xlsx":
            generate_xlsx_report(results, out, redact=args.redact)
        elif args.format == "term":
            print_colored_summary(results, redact=args.redact)
            generate_json_report(results, "reports/adaptive_report.json", redact=args.redact)
        print(f"[Report] Laporan disimpan di {out}")
        return

    # =========================================================
    # MODE NORMAL: InjectionEngine
    # =========================================================
    analyzer = SmartAnalyzer(
        pm.refusal,
        use_dual_model=not args.light,
        offline=args.offline,
        llm_judge_url=args.llm_judge,
        language=args.language,
        analysis_mode=args.analysis_mode
    )

    history = None
    if args.history:
        with open(args.history) as f:
            history = json.load(f)

    engine = InjectionEngine(
        conn, pm, analyzer,
        stealth=args.stealth,
        delay=args.delay,
        diff_mode=args.diff,
        attack_tree=args.attack_tree,
        max_depth=args.max_depth,
        workers=args.workers,
        language=args.language,
        rate_limiter=rate_limiter
    )

    if args.ai_only and not args.ai_payloads:
        sys.exit("[!] --ai-only requires --ai-payloads")

    if args.ai_only:
        print("[*] AI-only mode: template baseline campaign skipped.")
        results = []
    else:
        if args.attack_tree:
            print(f"[*] Memulai attack-tree ke {args.target} (max_depth={args.max_depth}, language={args.language})...")
        else:
            print(f"[*] Memulai kampanye {args.rounds} round ke {args.target}...")
        results = engine.run_campaign(
            rounds=args.rounds,
            category=args.category,
            mutate=args.mutate,
            aggressive=args.aggressive,
            adaptive=args.adaptive,
            history=history,
            multi_stage=args.multi_stage,
            audit=args.audit,
            target_endpoint=args.endpoint
        )

    # Adaptive local generation works with an explicit description or a derived
    # non-secret target profile, so --ai-payloads is not silently skipped.
    if ai_engine:
        ai_target_description = _derived_target_description(args)
        print("[*] Menghasilkan payload AI tambahan...")
        ai_payloads = ai_engine.generate(
            target_description=ai_target_description,
            context=None,
            n=args.rounds,
            language=args.language,
            strategy="instruction_boundary",
            target_fingerprint=ai_engine.target_fingerprint(args.endpoint or ai_target_description),
        )
        print(f"[*] Mendapat {len(ai_payloads)} payload AI. Mengirim...")

        # Shared circuit breaker prevents AI workers from continuing to hammer
        # a target after repeated exhausted HTTP 429 outcomes.
        ai_transport_breaker = TransportCircuitBreaker()

        # Fungsi kirim & analisis (sesuai API connector & analyzer sebenarnya)
        def process_ai_payload(payload):
            outcome = send_with_retry(
                lambda: conn.send(payload, []),
                max_attempts=3,
                rate_limiter=rate_limiter,
                circuit_breaker=ai_transport_breaker,
            )
            if not outcome.ok:
                return {
                    "round": -1,
                    "payload": payload,
                    "response": outcome.display_response,
                    "success": False,
                    "confidence": 0.0,
                    "method": "transport_error",
                    "leaked_data": [],
                    "diff": "",
                    "severity": "Info",
                    "leak_category": "",
                    "analysis_mode": args.analysis_mode,
                    "decision_reason": f"AI payload transport failure after {outcome.attempts} attempt(s): {outcome.error or 'Unknown error'}",
                    "evidence": [],
                    "language": args.language,
                    "transport_error": True,
                    "transport_attempts": outcome.attempts,
                    "transport_status_code": outcome.status_code,
                    "transport_retryable": outcome.retryable,
                }

            response = outcome.response or ""
            analysis = analyzer.analyze(payload, response)
            return {
                "round": -1,
                "payload": payload,
                "response": response,
                "success": analysis.get("success", False),
                "confidence": analysis.get("confidence", 0.0),
                "method": "ai_generated",
                "leaked_data": analysis.get("leaked_data", []),
                "diff": "",
                "severity": analysis.get("severity", "Info"),
                "leak_category": analysis.get("leak_category", ""),
                "analysis_mode": analysis.get("analysis_mode", args.analysis_mode),
                "decision_reason": analysis.get("decision_reason", ""),
                "evidence": analysis.get("evidence", []),
                "language": analysis.get("language", args.language),
                "transport_error": False,
                "transport_attempts": None,
                "transport_status_code": None,
                "transport_retryable": False,
            }

        ai_results = []
        if args.workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = [executor.submit(process_ai_payload, p) for p in ai_payloads]
                for future in concurrent.futures.as_completed(futures):
                    ai_results.append(future.result())
        else:
            for p in ai_payloads:
                ai_results.append(process_ai_payload(p))

        # Beri nomor round yang unik (melanjutkan hasil utama)
        next_round = len(results) + 1
        for r in ai_results:
            r["round"] = next_round
            next_round += 1
        results.extend(ai_results)

        # Simpan payload sukses ke AI database
        for r in ai_results:
            if r["success"]:
                ai_engine.record_success(
                    target_description=ai_target_description,
                    target_fingerprint=ai_engine.target_fingerprint(args.endpoint or ai_target_description),
                    payload=r["payload"],
                    leak_category=r.get("leak_category", "ai_probe"),
                    severity=r.get("severity", "Medium"),
                    evidence_summary=r.get("decision_reason", ""),
                    language=r.get("language", args.language),
                    probe_family="instruction_boundary",
                )
        print(f"[*] {len(ai_results)} payload AI selesai diproses.")

    # Summary
    success = sum(1 for r in results if r["success"])
    total = len(results)
    print(f"\n[Summary] {success}/{total} sukses ({success/total*100:.1f}%)" if total else "\n[Summary] No results")

    if not args.output:
        ext = {"json": "json", "html": "html", "csv": "csv", "pdf": "pdf", "xlsx": "xlsx", "term": "json"}[args.format]
        out = f"reports/report.{ext}"
    else:
        out = args.output

    if args.format == "json":
        generate_json_report(results, out, redact=args.redact)
    elif args.format == "html":
        generate_html_report(results, out, redact=args.redact)
    elif args.format == "csv":
        generate_csv_report(results, out, redact=args.redact)
    elif args.format == "pdf":
        generate_pdf_report(results, out, redact=args.redact)
    elif args.format == "xlsx":
        generate_xlsx_report(results, out, redact=args.redact)
    elif args.format == "term":
        print_colored_summary(results, redact=args.redact)
        generate_json_report(results, "reports/report.json", redact=args.redact)
    print(f"[Report] Laporan disimpan di {out}")


if __name__ == "__main__":
    main()    
