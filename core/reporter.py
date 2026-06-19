import csv
import html
import json
from pathlib import Path

from .redaction import redact_results

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = RESET_ALL = BRIGHT = DIM = NORMAL = ""
    Fore = Style = _NoColor()

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

try:
    from openpyxl import Workbook
    HAS_XLSX = True
except ImportError:
    HAS_XLSX = False


def _status_text(result):
    return "SUCCESS" if result.get("success") else "FAIL"


def _evidence_summary(result):
    evidence = result.get("evidence") or []
    if not evidence:
        return ""
    chunks = []
    for item in evidence[:5]:
        category = item.get("category", "")
        source = item.get("source", "")
        reason = item.get("reason", "")
        preview = item.get("value_preview", "")
        chunks.append(f"{category} via {source}: {preview} ({reason})")
    return " | ".join(chunks)


def generate_html_report(results, output_path, redact=False):
    results = redact_results(results, enabled=redact)
    rows = ""
    for r in results:
        cls = "success" if r.get("success") else "fail"
        rows += f"<tr class='{cls}'>"
        rows += f"<td>{html.escape(str(r.get('round', '')))}</td>"
        rows += f"<td><code>{html.escape(str(r.get('payload', ''))[:160])}</code></td>"
        rows += f"<td>{html.escape(str(r.get('response', ''))[:220])}</td>"
        rows += f"<td><span class='badge {cls}'>{_status_text(r)}</span></td>"
        rows += f"<td>{float(r.get('confidence', 0)):.2f}</td>"
        rows += f"<td>{html.escape(str(r.get('severity', 'Info')))}</td>"
        rows += f"<td>{html.escape(str(r.get('leak_category', '')))}</td>"
        rows += f"<td>{html.escape(str(r.get('method', '')))}</td>"
        rows += f"<td>{html.escape(str(r.get('analysis_mode', '')))}</td>"
        rows += f"<td>{html.escape(str(r.get('decision_reason', '')))}</td>"
        rows += f"<td>{html.escape(_evidence_summary(r))}</td>"
        rows += "</tr>"

    total = len(results)
    success = sum(1 for r in results if r.get("success"))
    critical = sum(1 for r in results if r.get("severity") == "Critical")
    html_content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>InjectionForge Pro X Report</title>
<style>
:root {{ --bg:#0f172a; --panel:#111827; --line:#d1d5db; --text:#111827; --muted:#6b7280; --ok:#065f46; --bad:#991b1b; }}
body {{ margin:0; font-family:Inter, Segoe UI, Arial, sans-serif; background:#f8fafc; color:var(--text); }}
header {{ background:var(--bg); color:white; padding:28px 36px; }}
header h1 {{ margin:0 0 8px 0; font-size:28px; }}
header p {{ margin:0; color:#cbd5e1; }}
main {{ padding:28px 36px; }}
.cards {{ display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; }}
.card {{ background:white; border:1px solid #e5e7eb; border-radius:10px; padding:16px 18px; min-width:160px; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
.card .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
.card .value {{ font-size:26px; font-weight:700; margin-top:4px; }}
table {{ border-collapse:collapse; width:100%; background:white; border:1px solid #e5e7eb; border-radius:10px; overflow:hidden; }}
th {{ background:#111827; color:white; font-size:12px; letter-spacing:.04em; text-transform:uppercase; padding:10px; text-align:left; }}
td {{ padding:10px; border-top:1px solid #e5e7eb; vertical-align:top; font-size:13px; }}
code {{ white-space:pre-wrap; word-break:break-word; }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:999px; color:white; font-size:12px; font-weight:700; }}
.badge.success {{ background:var(--ok); }}
.badge.fail {{ background:var(--bad); }}
tr.success {{ background:#f0fdf4; }}
tr.fail {{ background:#fff7ed; }}
</style>
</head>
<body>
<header>
<h1>InjectionForge Pro X Report</h1>
<p>Evidence-gated prompt injection and sensitive disclosure assessment.</p>
</header>
<main>
<section class="cards">
<div class="card"><div class="label">Total Results</div><div class="value">{total}</div></div>
<div class="card"><div class="label">Successful Findings</div><div class="value">{success}</div></div>
<div class="card"><div class="label">Critical Findings</div><div class="value">{critical}</div></div>
</section>
<table>
<tr><th>Round</th><th>Payload</th><th>Response</th><th>Status</th><th>Confidence</th><th>Severity</th><th>Category</th><th>Method</th><th>Mode</th><th>Reason</th><th>Evidence</th></tr>
{rows}
</table>
</main>
</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")


def generate_json_report(results, output_path, redact=False):
    results = redact_results(results, enabled=redact)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def generate_csv_report(results, output_path, redact=False):
    results = redact_results(results, enabled=redact)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "round", "payload", "response", "success", "confidence", "method", "severity",
            "leak_category", "analysis_mode", "decision_reason", "evidence", "leaked_data"
        ])
        for r in results:
            writer.writerow([
                r.get("round", ""), r.get("payload", ""), r.get("response", ""),
                r.get("success", False), r.get("confidence", 0), r.get("method", ""),
                r.get("severity", "Info"), r.get("leak_category", ""), r.get("analysis_mode", ""),
                r.get("decision_reason", ""), _evidence_summary(r), json.dumps(r.get("leaked_data", []), ensure_ascii=False)
            ])


def generate_pdf_report(results, output_path, redact=False):
    results = redact_results(results, enabled=redact)
    if not HAS_PDF:
        print("[WARN] reportlab is not installed. Install it with: pip install reportlab")
        return
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("InjectionForge Pro X Report", styles["Title"]))
    elements.append(Paragraph("Evidence-gated prompt injection and sensitive disclosure assessment.", styles["BodyText"]))
    elements.append(Spacer(1, 12))
    data = [["Round", "Status", "Confidence", "Severity", "Category", "Method", "Reason"]]
    for r in results:
        data.append([
            str(r.get("round", "")),
            _status_text(r),
            f"{r.get('confidence', 0):.2f}",
            r.get("severity", "Info"),
            r.get("leak_category", ""),
            r.get("method", ""),
            r.get("decision_reason", "")[:90],
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    elements.append(table)
    doc.build(elements)


def generate_xlsx_report(results, output_path, redact=False):
    results = redact_results(results, enabled=redact)
    if not HAS_XLSX:
        print("[WARN] openpyxl is not installed. Install it with: pip install openpyxl")
        return
    wb = Workbook()
    ws = wb.active
    ws.title = "InjectionForge Report"
    ws.append([
        "Round", "Payload", "Response", "Status", "Confidence", "Severity", "Category",
        "Method", "Mode", "Reason", "Evidence", "Leaked Data"
    ])
    for r in results:
        ws.append([
            r.get("round", ""),
            r.get("payload", ""),
            r.get("response", ""),
            _status_text(r),
            r.get("confidence", 0),
            r.get("severity", "Info"),
            r.get("leak_category", ""),
            r.get("method", ""),
            r.get("analysis_mode", ""),
            r.get("decision_reason", ""),
            _evidence_summary(r),
            ", ".join(r.get("leaked_data", [])),
        ])
    wb.save(output_path)


def print_colored_summary(results, redact=False):
    results = redact_results(results, enabled=redact)
    for r in results:
        status = f"{Fore.GREEN}SUCCESS" if r.get("success") else f"{Fore.RED}FAIL"
        print(f"{Style.BRIGHT}Round {r.get('round')}{Style.RESET_ALL}: {status} "
              f"(conf={r.get('confidence', 0):.2f}, method={r.get('method')}, severity={r.get('severity','Info')})")
        if r.get("decision_reason"):
            print(f"   Reason: {r.get('decision_reason')}")
        if r.get("evidence"):
            print(f"   Evidence: {_evidence_summary(r)}")
        if r.get("leaked_data"):
            print(f"   Leaked: {r.get('leaked_data')}")
        if r.get("diff"):
            print(f"   Diff:\n{r.get('diff', '')[:200]}")
