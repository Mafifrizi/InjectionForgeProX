import html
import json
import csv
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# ---------- PDF (reportlab) ----------
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

# ---------- XLSX (openpyxl) ----------
try:
    from openpyxl import Workbook
    HAS_XLSX = True
except ImportError:
    HAS_XLSX = False


def generate_html_report(results, output_path):
    rows = ""
    for r in results:
        cls = "success" if r["success"] else "fail"
        rows += f"<tr class='{cls}'>"
        rows += f"<td>{r['round']}</td>"
        rows += f"<td>{html.escape(r['payload'][:100])}</td>"
        rows += f"<td>{html.escape(r['response'][:150])}</td>"
        rows += f"<td>{'✅' if r['success'] else '❌'}</td>"
        rows += f"<td class='conf'>{r['confidence']:.2f}</td>"
        rows += f"<td>{html.escape(r.get('method',''))}</td>"
        rows += f"<td>{html.escape(r.get('severity','Info'))}</td>"
        rows += "</tr>"

    html_content = f"""<html><head><title>InjectionForge Report</title>
    <style>
    body{{font-family:Arial;margin:20px;background:#f5f5f5}}
    table{{border-collapse:collapse;width:100%;background:#fff}}
    th{{background:#333;color:#fff;padding:8px}}
    td{{padding:8px;border-bottom:1px solid #ddd}}
    .success{{background:#e6ffe6}} .fail{{background:#ffe6e6}} .conf{{font-weight:bold}}
    </style></head><body>
    <h1>InjectionForge Pro X - Report</h1>
    <table>
    <tr><th>Round</th><th>Payload</th><th>Response</th><th>Success</th><th>Confidence</th><th>Method</th><th>Severity</th></tr>
    {rows}
    </table></body></html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")


def generate_json_report(results, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def generate_csv_report(results, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["round", "payload", "response", "success", "confidence", "method", "leaked_data", "severity"])
        for r in results:
            writer.writerow([
                r["round"], r["payload"], r["response"],
                r["success"], r["confidence"], r["method"],
                json.dumps(r.get("leaked_data", [])), r.get("severity", "Info")
            ])


def generate_pdf_report(results, output_path):
    if not HAS_PDF:
        print("[!] reportlab tidak terinstal. Install dengan: pip install reportlab")
        return
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("InjectionForge Pro X - Report", styles["Title"]))
    data = [["Round", "Payload", "Response", "Success", "Confidence", "Severity", "Category"]]
    for r in results:
        data.append([
            str(r.get("round", "")),
            r.get("payload", "")[:80],
            r.get("response", "")[:80],
            "Yes" if r.get("success") else "No",
            f"{r.get('confidence', 0):.2f}",
            r.get("severity", "Info"),
            r.get("leak_category", ""),
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    doc.build(elements)


def generate_xlsx_report(results, output_path):
    if not HAS_XLSX:
        print("[!] openpyxl tidak terinstal. Install dengan: pip install openpyxl")
        return
    wb = Workbook()
    ws = wb.active
    ws.title = "InjectionForge Report"
    ws.append(["Round", "Payload", "Response", "Success", "Confidence", "Severity", "Category", "Leaked Data"])
    for r in results:
        ws.append([
            r.get("round", ""),
            r.get("payload", ""),
            r.get("response", ""),
            "Yes" if r.get("success") else "No",
            r.get("confidence", 0),
            r.get("severity", "Info"),
            r.get("leak_category", ""),
            ", ".join(r.get("leaked_data", [])),
        ])
    wb.save(output_path)


def print_colored_summary(results):
    for r in results:
        status = f"{Fore.GREEN}✅ SUCCESS" if r["success"] else f"{Fore.RED}❌ FAIL"
        print(f"{Style.BRIGHT}Round {r['round']}{Style.RESET_ALL}: {status} "
              f"(conf={r['confidence']:.2f}, method={r['method']}, severity={r.get('severity','Info')})")
        if r.get("leaked_data"):
            print(f"   {Fore.YELLOW}Leaked: {r['leaked_data']}")
        if r.get("diff"):
            print(f"   {Fore.CYAN}Diff:\n{r['diff'][:200]}")