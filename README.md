# 🧪 InjectionForge Pro X v3.4 – Full Spectrum Edition

**Advanced AI Agent & Chatbot Prompt Injection Testing Framework**

[![Tests](https://img.shields.io/badge/tests-15%2F15%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.4.0-orange)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

---

## 📖 Daftar Isi

- [Fitur Utama](#-fitur-utama)
- [Instalasi](#-instalasi)
- [Validasi Analyzer](#-validasi-analyzer)
- [Penggunaan Dasar](#-penggunaan-dasar)
  - [1. Mock Target](#1-mock-target)
  - [2. Model Lokal (Ollama)](#2-model-lokal-ollama)
  - [3. REST API](#3-rest-api)
  - [4. GraphQL](#4-graphql)
  - [5. WebSocket](#5-websocket)
  - [6. WAF Bypass](#6-waf-bypass)
  - [7. Auto‑Discovery](#7-auto‑discovery)
- [Output](#-output)
- [Struktur Proyek](#-struktur-proyek)
- [Berkontribusi](#-berkontribusi)
- [Lisensi](#-lisensi)

---

## 🚀 Fitur Utama

- 🔌 **Multi‑protocol** – REST, WebSocket, Server‑Sent Events, GraphQL
- 🛡️ **WAF bypass** – Cloudflare, Akamai, auto‑detect, TLS fingerprint randomization, headless browser
- 🧠 **Payload generator adaptif** – 200+ template (universal, bisnis, indirect, GraphQL, WebSocket)
- 🔍 **Analyzer 3‑lapis** – Refusal detection + Regex presisi + Semantic voting → **false positive < 1%**
- 🥷 **Stealth mode** – Random User‑Agent, delay jitter, proxy support
- 🔎 **Auto‑discovery** – Ekstrak endpoint chat dari halaman web
- 🔐 **Auto‑login** – Login form & session management
- 📊 **Audit mode** – Eksploitasi logika bisnis (error handling, input validation)
- 📄 **Output multi‑format** – JSON, HTML, CSV, terminal berwarna
- 🧪 **15 unit test** – Semua lulus

---

## 📦 Instalasi

```bash
git https://github.com/Mafifrizi/InjectionForgeProX.git
cd InjectionForgeProX
pip install -r requirements.txt
playwright install   # hanya untuk mode headless
```

---

## 🧪 Validasi Analyzer

**Sebelum digunakan, pastikan analyzer memiliki presisi ≥ 95%:**

```bash
python forge_x.py --validate --light --offline
```

---

## ⚡ Penggunaan Dasar

**1. Mock Target**

```bash
python forge_x.py --target mock --rounds 10 --aggressive --format json --offline
```

**2. Model Lokal (Ollama)**

```bash
python forge_x.py --target ollama --model llama3 --category advanced --rounds 20 --aggressive --format json --offline
```

**3. REST API**

```bash
python forge_x.py --target custom --endpoint "https://api.umkm.com/chat" \
  --method POST --json-path "reply" --audit --rounds 20 --format html --offline
```

**4. GraphQL**

```bash
python forge_x.py --target graphql --endpoint "https://api.umkm.com/graphql" \
  --category graphql --rounds 20 --aggressive --format json --offline
```

**5. WebSocket**

```bash
python forge_x.py --target custom --method WS --endpoint "wss://chat.umkm.com/ws" \
  --rounds 10 --aggressive --format json --offline
``` 

**6. WAF Bypass**

```bash
python forge_x.py --target custom --endpoint "https://protected.umkm.com/api/chat" \
  --bypass-waf auto --tls-fingerprint random --stealth --aggressive --rounds 20
```

**7. Auto‑Discovery**

```bash
python forge_x.py --target auto --discover --endpoint "https://umkm.com/chat-page" \
  --auto-profile --rounds 20 --format json --offline
```

---

## 📊 Output

Laporan disimpan di folder `reports/`.

| Format   | Perintah        |
|----------|-----------------|
| JSON     | `--format json` |
| HTML     | `--format html` |
| CSV      | `--format csv`  |
| Terminal | `--format term` |

### Contoh entri sukses:

```json
{
  "round": 7,
  "payload": "pesan jumlah 0",
  "response": "Error: Token internal: umkm-public-token-2025",
  "success": true,
  "confidence": 0.98,
  "leaked_data": ["umkm-public-token-2025"],
  "severity": "High"
}
``` 

---

## 🧩 Struktur Proyek

```text
InjectionForgeProX/
├── forge_x.py                  # CLI utama
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── core/
│   ├── __init__.py
│   ├── engine.py
│   ├── payloads.py
│   ├── payload_generator.py
│   ├── obfuscator.py
│   ├── analyzer.py
│   ├── validator.py
│   ├── reporter.py
│   ├── waf_bypass.py
│   ├── profiler.py
│   ├── auth.py
│   ├── auto_discovery.py
│   ├── utils.py
│   └── connectors/
│       ├── __init__.py
│       ├── base.py
│       ├── rest.py
│       ├── websocket.py
│       ├── sse.py
│       ├── graphql.py
│       ├── ollama.py
│       ├── openai.py
│       ├── claude.py
│       ├── gemini.py
│       ├── cohere.py
│       ├── huggingface.py
│       └── mock_target.py
│
├── data/
│   ├── payloads_basic.json
│   ├── payloads_advanced.json
│   ├── payloads_indirect.json
│   ├── payloads_agent.json
│   ├── payloads_graphql.json
│   ├── refusal_phrases.txt
│   ├── labeled_test_set.json
│   └── user_agents.txt
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_payload_manager.py
│   ├── test_obfuscator.py
│   ├── test_connectors.py
│   └── test_integration.py
│
└── reports/                    # Auto-generated
```

---

## 🤝 Berkontribusi

Kontribusi sangat diterima! Silakan buka issue atau pull request.

### Langkah-langkah

1. Fork repositori

2. Buat branch fitur

```bash
git checkout -b fitur-keren
```

3. Commit perubahan

```bash
git commit -m "Tambah fitur keren"
```

4. Push ke branch

```bash
git push origin fitur-keren
```

5. Buka Pull Request



