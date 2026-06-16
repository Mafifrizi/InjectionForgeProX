# 🧪 InjectionForge Pro X v1.0 – Full Spectrum Edition

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

## 🆘 Bantuan (CLI Reference)

Jalankan `python forge_x.py --help` untuk melihat semua opsi. Berikut ringkasan flag utama:

### 🔌 Target & Koneksi
| Flag | Deskripsi | Contoh |
|------|-----------|--------|
| `--target` | Jenis target: `auto`, `mock`, `custom`, `openai`, `claude`, `gemini`, `cohere`, `ollama`, `huggingface`, `graphql` | `--target custom` |
| `--endpoint` | URL endpoint API/chat | `--endpoint https://api.umkm.com/chat` |
| `--method` | HTTP method (`POST`, `GET`, `WS`, `SSE`) | `--method POST` |
| `--headers` | Header tambahan (JSON atau `Key:Val`) | `--headers '{"Authorization":"Bearer xyz"}'` |
| `--cookie` | Cookie string atau file | `--cookie "session=abc123"` |
| `--json-path` | Jalur ke teks respons (contoh: `data.reply`) | `--json-path "data.text"` |
| `--form` | Kirim sebagai form‑encoded | `--form` |
| `--timeout` | Timeout request (detik) | `--timeout 30` |

### 🧠 Payload & Serangan
| Flag | Deskripsi | Contoh |
|------|-----------|--------|
| `--category` | Kategori payload: `basic`, `advanced`, `indirect`, `agent`, `graphql` | `--category advanced` |
| `--rounds` | Jumlah percobaan | `--rounds 20` |
| `--mutate` | Aktifkan mutasi standar (base64, ROT13, dll.) | `--mutate` |
| `--aggressive` | Mutasi agresif + generator jika database kosong | `--aggressive` |
| `--audit` | Mode audit: payload bisnis tanpa mutasi | `--audit` |
| `--adaptive` | Payload adaptif berdasarkan bobot keberhasilan | `--adaptive` |
| `--multi-stage` | Serangan 2‑langkah (priming + exploitation) | `--multi-stage` |

### 🛡️ WAF & Stealth
| Flag | Deskripsi | Contoh |
|------|-----------|--------|
| `--bypass-waf` | `cloudflare`, `akamai`, `auto`, `none` | `--bypass-waf auto` |
| `--tls-fingerprint` | `random`, `chrome`, `firefox`, `safari` | `--tls-fingerprint random` |
| `--headless` | Gunakan headless browser untuk JS challenge | `--headless` |
| `--stealth` | Random User‑Agent + delay jitter | `--stealth` |
| `--delay` | Delay dasar antar request (detik) | `--delay 1.5` |
| `--proxy` | Proxy URL | `--proxy http://127.0.0.1:8080` |
| `--insecure` | Matikan verifikasi SSL (hanya untuk testing internal) | `--insecure` |

### 🔍 Discovery & Profiling
| Flag | Deskripsi | Contoh |
|------|-----------|--------|
| `--discover` | Auto‑discover endpoint dari halaman web | `--discover` |
| `--auto-profile` | Profil target & pilih strategi otomatis | `--auto-profile` |
| `--waf-detect` | Deteksi WAF tanpa menjalankan serangan | `--waf-detect` |
| `--graphql-introspect` | Introspect GraphQL schema | `--graphql-introspect` |

### 📊 Output
| Flag | Deskripsi | Contoh |
|------|-----------|--------|
| `--format` | `json`, `html`, `csv`, `term` | `--format html` |
| `--output` | File laporan (default: `reports/report.json`) | `--output audit.html` |
| `--diff` | Bandingkan respons dengan baseline (prompt netral) | `--diff` |

### ⚙️ Validasi & Mode Khusus
| Flag | Deskripsi |
|------|-----------|
| `--validate` | Self‑test analyzer (presisi ≥ 95%) |
| `--light` | Gunakan hanya satu model (lebih ringan) |
| `--offline` | Mode offline: tidak unduh model, hanya regex+refusal |

---

## 🚀 Fitur Utama

Framework ini menyediakan fondasi yang solid untuk pengujian keamanan prompt injection:

- 🔌 **Multi‑protocol** – REST, WebSocket, Server‑Sent Events, GraphQL, dan konektor untuk Ollama, OpenAI, Claude, Gemini, Cohere, Hugging Face.
- 🛡️ **WAF evasion** – Cloudscraper, curl_cffi, TLS fingerprint randomization, dan dukungan headless browser (eksperimental).
- 🧠 **Payload generator** – 200+ template (universal, bisnis, GraphQL, WebSocket) dengan mutasi agresif (Unicode, emoji, RTL).
- 🔍 **Analyzer 3‑lapis** – Refusal detection + pola regex spesifik + semantic similarity (MiniLM/DistilRoBERTa).
- 🥷 **Stealth mode** – Rotasi User‑Agent, delay jitter, dan dukungan proxy.
- 🔎 **Auto‑discovery** – Mencari endpoint chat dari halaman web.
- 🔐 **Auto‑login** – Dukungan login form & session management.
- 📊 **Audit mode** – Fokus pada logika bisnis (error handling, input validation).
- 📄 **Output multi‑format** – JSON, HTML, CSV, terminal berwarna.
- 🧪 **15 unit test** – Memvalidasi komponen inti.

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

## ⚠️ Keterbatasan & Roadmap

Tool ini adalah **kerangka kerja (framework) open‑source**, bukan *enterprise product*.  
Beberapa keterbatasan yang perlu diketahui:

- **Payload generator** masih berbasis template. Untuk target modern, payload mungkin perlu disesuaikan secara manual.
- **Analyzer** mengandalkan kombinasi regex dan semantic similarity. False positive bisa terjadi pada respons yang meniru kebocoran (misalnya roleplay).
- **WAF bypass** belum mencakup teknik canggih seperti JA3 spoofing atau HTTP/2 fingerprint control. Fitur headless masih eksperimental.
- **Belum ada benchmark independen** untuk mengukur presisi/recall di berbagai model.

Rencana pengembangan selanjutnya:
- [ ] Integrasi JA3/JA4 fingerprint randomization penuh
- [ ] Response clustering & confidence scoring berbasis embedding
- [ ] Multi‑turn attack tree
- [ ] Benchmark dataset publik (Gandalf, HackAPrompt)
- [ ] Dashboard web untuk visualisasi hasil

Kontribusi sangat diterima! Silakan buka *issue* atau *pull request*.

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



