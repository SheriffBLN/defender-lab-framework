import csv
import os
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTEXT_PATH = os.path.join(BASE_DIR, "tools", "input_context.json")

STATUS_COLORS = {
    "Tested": "#d4edda",
    "Audit": "#fff3cd",
    "Pending": "#f8d7da"
}

def load_context():
    with open(CONTEXT_PATH, encoding="utf-8") as f:
        return json.load(f)

def get_csv_path(context):
    apt = context["apt_name"] if context.get("apt_mode") else "SingleTechnique"
    return os.path.join(BASE_DIR, "mapping", apt, "status.csv"), apt

def main():
    context = load_context()
    csv_path, apt = get_csv_path(context)
    output_path = os.path.join(BASE_DIR, "report", apt, "index.html")

    if not Path(csv_path).exists():
        print(f"[!] Brak pliku status.csv pod: {csv_path}")
        return

    with open(csv_path, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if not rows:
        print("[!] Plik status.csv jest pusty.")
        return

    total = len(rows)
    status_counts = Counter(r['Status'] for r in rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[05] Znaleziono {total} technik. Generowanie sekcji...")

    tactic_groups = defaultdict(list)
    for r in rows:
        for t in r['Tactics'].split(','):
            tac = t.strip().capitalize()
            if tac:
                tactic_groups[tac].append(r)

    html = [
        '<!DOCTYPE html>', '<html>', '<head>', '  <meta charset="UTF-8">',
        f'  <title>Raport {apt}</title>', '  <style>',
        '    body { font-family: Arial, sans-serif; padding:20px; }',
        '    h1 { border-bottom:2px solid #333; }',
        '    table { width:100%; border-collapse: collapse; margin-bottom:20px; }',
        '    th, td { border:1px solid #999; padding:8px; text-align:left; }',
        '    th { background:#eee; }', '    ul { margin-bottom:20px; }',
        '  </style>', '</head>', '<body>',
        f'  <h1>Raport: {apt}</h1>', f'  <p>Wygenerowano: {now}</p>',
        f'  <p>Łączna liczba technik: {total}</p>', '  <ul>'
    ]
    for status, count in status_counts.items():
        html.append(f'    <li>{status}: {count}</li>')
    html.append('  </ul>')

    # Sekcje MITRE (kolejność logiczna z merge!)
    mitre_order = [
        "Initial-Access", "Execution", "Persistence", "Privilege-Escalation", "Defense-Evasion",
        "Credential-Access", "Discovery", "Lateral-Movement", "Collection",
        "Command-And-Control", "Exfiltration", "Impact"
    ]
    for tactic in mitre_order:
        group = tactic_groups.get(tactic, [])
        if not group:
            continue
        html.append(f"  <h2>{tactic}</h2>")
        html.append('  <table>')
        html.append('    <tr><th>Technique ID</th><th>Name</th><th>Status</th><th>Linked Rule</th></tr>')
        for r in group:
            bg = STATUS_COLORS.get(r['Status'], '#ffffff')
            link = r['Linked Rule']
            html.append(
                f"    <tr style='background:{bg};'>"
                f"<td>{r['Technique ID']}</td>"
                f"<td>{r['Name']}</td>"
                f"<td>{r['Status']}</td>"
                f"<td><a href='{link}' target='_blank'>{link}</a></td>"
                "</tr>"
            )
        html.append('  </table>')

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(html))

    print(f"[✓] Raport zapisany do: {output_path}")

if __name__ == "__main__":
    main()
