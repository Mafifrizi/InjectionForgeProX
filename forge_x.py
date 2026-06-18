import argparse
import sys
import os
import json
import concurrent.futures
from pathlib import Path

from core.payloads import PayloadManager
from core.analyzer import SmartAnalyzer
from core.engine import InjectionEngine
from core.validator import validate_analyzer
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
from core.payload_engine import AIPayloadEngine   # PATCH


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
        return dict(kv.split("=") for kv in val.split(",") if "=" in kv)


def main():
    parser = argparse.ArgumentParser(
        description="InjectionForge Pro X v1.0 – Full Spectrum",
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

  # Adaptive agent multi‑turn dengan auto‑profiling
  python forge_x.py --target custom --endpoint "http://127.0.0.1:5000/v1/chat" --adaptive-agent --rounds 10 --headers "X-API-Key:masta-dev-123"

  # AI‑generated payloads + multi‑threading (menggunakan worker bawaan engine)
  python forge_x.py --target custom --endpoint "https://api.umkm.com/chat" --ai-payloads --workers 4 --rounds 20 --format json
        """
    )

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

    # Payload & serangan
    parser.add_argument("--rounds", type=int, default=10, help="Jumlah percobaan injeksi")
    parser.add_argument("--category", choices=["basic","advanced","indirect","agent","graphql"], default="basic", help="Kategori payload")
    parser.add_argument("--mutate", action="store_true", help="Aktifkan mutasi standar (base64, ROT13, dll.)")
    parser.add_argument("--aggressive", action="store_true", help="Mutasi agresif + generator jika database kosong")
    parser.add_argument("--adaptive", action="store_true", help="Payload adaptif berdasarkan bobot keberhasilan")
    parser.add_argument("--multi-stage", action="store_true", help="Serangan 2‑langkah (priming + exploitation)")
    parser.add_argument("--history", help="File JSON conversation history")
    parser.add_argument("--audit", action="store_true", help="Mode audit: payload bisnis tanpa mutasi")
    parser.add_argument("--attack-tree", action="store_true", help="Gunakan attack tree multi‑turn adaptif")
    parser.add_argument("--max-depth", type=int, default=2, help="Kedalaman maksimum attack tree")
    parser.add_argument("--workers", type=int, default=4, help="Jumlah thread untuk multi-threading")
    parser.add_argument("--ai-payloads", action="store_true", help="Gunakan AIPayloadEngine (LLM lokal) untuk generate payload tambahan")

    # Fitur baru: Adaptive Agent & LLM Generator
    parser.add_argument("--adaptive-agent", action="store_true", help="Gunakan adaptive multi‑turn agent dengan auto‑profiling")
    parser.add_argument("--target-description", help="Deskripsi target opsional. Jika dikosongkan, akan diisi otomatis.")

    # Output
    parser.add_argument("--output", help="File laporan (default: reports/report.json)")
    parser.add_argument("--format", choices=["json","html","csv","pdf","xlsx","term"], default="json", help="Format laporan")
    parser.add_argument("--diff", action="store_true", help="Bandingkan respons dengan baseline (prompt netral)")

    # Validasi
    parser.add_argument("--validate", action="store_true", help="Self‑test analyzer (presisi >= 95%)")
    parser.add_argument("--light", action="store_true", help="Gunakan hanya satu model (lebih ringan)")
    parser.add_argument("--offline", action="store_true", help="Mode offline: tidak unduh model, hanya regex+refusal")

    # Discovery & profiling
    parser.add_argument("--discover", action="store_true", help="Auto‑discovery endpoint dari halaman web")
    parser.add_argument("--auto-profile", action="store_true", default=True, help="Profil target & pilih strategi otomatis")
    parser.add_argument("--waf-detect", action="store_true", help="Deteksi WAF tanpa menjalankan serangan")
    parser.add_argument("--graphql-introspect", action="store_true", help="Introspect GraphQL schema sebelum serangan")

    # WAF bypass
    parser.add_argument("--bypass-waf", choices=["cloudflare","akamai","auto","none"], default="none", help="Bypass WAF (cloudflare, akamai, auto)")
    parser.add_argument("--tls-fingerprint", choices=["random","chrome","firefox","safari"], default="none", help="TLS fingerprint untuk hindari deteksi")
    parser.add_argument("--headless", action="store_true", help="Gunakan headless browser untuk JS challenge")

    # Keamanan koneksi
    parser.add_argument("--insecure", action="store_true", help="Nonaktifkan verifikasi SSL (hanya untuk testing internal yang sah!)")
    parser.add_argument("--llm-judge", help="URL Ollama untuk LLM judge (contoh: http://localhost:11434)")

    args = parser.parse_args()
    init_db()

    # Validasi analyzer
    if args.validate:
        ok = validate_analyzer(light=args.light, offline=args.offline)
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
        print(f"[*] Mencari endpoint dari {args.endpoint}...")
        discovered = discover_endpoint(args.endpoint, insecure=args.insecure)
        if discovered:
            args.endpoint = discovered["endpoint"]
            args.method = discovered.get("method", "POST")
            args.json_path = discovered.get("json_path", None)
            print(f"   Ditemukan: {args.method} {args.endpoint}")
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
        profiler = TargetProfiler(args.endpoint, args.method, parse_headers(args.headers), insecure=args.insecure)
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
        if args.method.upper() == "WS":
            from core.connectors.websocket import WebSocketConnector
            conn = WebSocketConnector(endpoint=args.endpoint, timeout=args.timeout)
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
        pm = PayloadManager()
    except Exception as e:
        sys.exit(f"[!] Payload error: {e}")

    # Inisialisasi AIPayloadEngine jika diminta
    ai_engine = None
    if args.ai_payloads:
        ai_engine = AIPayloadEngine(
            db_path="data/payloads.db",
            ollama_url=args.llm_judge or "http://localhost:11434"
        )
        print("[*] AIPayloadEngine aktif – akan generate payload AI.")

    # =========================================================
    # Adaptive Agent (dengan kemungkinan override generator)
    # =========================================================
    if args.adaptive_agent:
        from core.adaptive_agent import AdaptiveAgent
        from core.llm_generator import LLMGenerator

        llm_gen = LLMGenerator()
        if ai_engine:
            class AIWrapper:
                def generate(self, prompt, **kwargs):
                    desc = args.target_description or "generic target"
                    return ai_engine.generate(desc, context=None, n=1)[0]
            llm_gen = AIWrapper()
            print("[*] Adaptive Agent akan menggunakan AIPayloadEngine untuk payload.")

        adaptive_analyzer = SmartAnalyzer(
            pm.refusal,
            use_dual_model=False,
            offline=True,
            llm_judge_url=args.llm_judge or "http://localhost:11434"
        )
        agent = AdaptiveAgent(conn, adaptive_analyzer, llm_gen=llm_gen)

        if not args.target_description:
            print("[*] Auto-profiling target...")
            auto_desc = agent.auto_profile()
            print(f"[*] Profil otomatis: {auto_desc[:100]}...")
        else:
            agent.target_description = args.target_description
            print(f"[*] Menggunakan deskripsi manual: {args.target_description}")

        print(f"[*] Adaptive Agent aktif. Target: {agent.target_description}")
        results = agent.run_adaptive_session(max_turns=args.rounds)

        success = sum(1 for r in results if r["success"])
        total = len(results)
        print(f"\n[Summary] {success}/{total} sukses ({(success/total)*100:.1f}%)" if total else "\n[Summary] No results")

        if ai_engine:
            for r in results:
                if r["success"]:
                    ai_engine.record_success(
                        target_description=args.target_description or "adaptive_session",
                        payload=r["payload"],
                        leak_category=r.get("leak_category", "unknown"),
                        severity=r.get("severity", "Medium")
                    )

        for i, r in enumerate(results, 1):
            status = "✅" if r["success"] else "❌"
            cat = r.get("leak_category", "")
            sev = r.get("severity", "Info")
            print(f"  Turn {i} [{r['strategy']}]: {r['payload'][:80]}... -> {status} {cat}/{sev}")

        out = args.output or f"reports/adaptive_report.{args.format if args.format != 'term' else 'json'}"
        if args.format == "json":
            generate_json_report(results, out)
        elif args.format == "html":
            generate_html_report(results, out)
        elif args.format == "csv":
            generate_csv_report(results, out)
        elif args.format == "pdf":
            generate_pdf_report(results, out)
        elif args.format == "xlsx":
            generate_xlsx_report(results, out)
        elif args.format == "term":
            print_colored_summary(results)
            generate_json_report(results, "reports/adaptive_report.json")
        print(f"[Report] Laporan disimpan di {out}")
        return

    # =========================================================
    # MODE NORMAL: InjectionEngine
    # =========================================================
    analyzer = SmartAnalyzer(
        pm.refusal,
        use_dual_model=not args.light,
        offline=args.offline,
        llm_judge_url=args.llm_judge
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
        workers=args.workers
    )

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

    # ========== PATCH: AI Payloads (tambahan) ==========
    if ai_engine and args.target_description:
        print("[*] Menghasilkan payload AI tambahan...")
        ai_payloads = ai_engine.generate(
            target_description=args.target_description,
            context=None,
            n=args.rounds
        )
        print(f"[*] Mendapat {len(ai_payloads)} payload AI. Mengirim...")

        # Fungsi kirim & analisis (sesuai API connector & analyzer sebenarnya)
        def process_ai_payload(payload):
            try:
                resp = conn.send(payload, [])  # history kosong
                analysis = analyzer.analyze(payload, resp)
                success = analysis.get("success", False)
                return {
                    "round": -1,  # akan di‑assign nanti
                    "payload": payload,
                    "response": resp,
                    "success": success,
                    "confidence": analysis.get("confidence", 0.0),
                    "method": "ai_generated",
                    "leaked_data": analysis.get("leaked_data", []),
                    "diff": "",
                    "severity": analysis.get("severity", "Info")
                }
            except Exception as e:
                return {
                    "round": -1,
                    "payload": payload,
                    "response": str(e),
                    "success": False,
                    "confidence": 0.0,
                    "method": "ai_generated",
                    "leaked_data": [],
                    "diff": "",
                    "severity": "Info"
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
                    target_description=args.target_description,
                    payload=r["payload"],
                    leak_category="ai_injection",
                    severity=r.get("severity", "Medium")
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
        generate_json_report(results, out)
    elif args.format == "html":
        generate_html_report(results, out)
    elif args.format == "csv":
        generate_csv_report(results, out)
    elif args.format == "pdf":
        generate_pdf_report(results, out)
    elif args.format == "xlsx":
        generate_xlsx_report(results, out)
    elif args.format == "term":
        print_colored_summary(results)
        generate_json_report(results, "reports/report.json")
    print(f"[Report] Laporan disimpan di {out}")


if __name__ == "__main__":
    main()