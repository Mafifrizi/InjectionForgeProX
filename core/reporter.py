import html
import json
import csv
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)


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
        rows += f"<td>{html.escape(r['method'])}</td>"
        rows += f"<td>{html.escape(r.get('severity', 'Info'))}</td>"
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


def print_colored_summary(results):
    for r in results:
        status = f"{Fore.GREEN}✅ SUCCESS" if r["success"] else f"{Fore.RED}❌ FAIL"
        print(f"{Style.BRIGHT}Round {r['round']}{Style.RESET_ALL}: {status} "
            f"(conf={r['confidence']:.2f}, method={r['method']}, severity={r.get('severity','Info')})")
        if r.get("leaked_data"):
            print(f"   {Fore.YELLOW}Leaked: {r['leaked_data']}")
        if r.get("diff"):
            print(f"   {Fore.CYAN}Diff:\n{r['diff'][:200]}")