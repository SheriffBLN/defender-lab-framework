import os
import csv
import json
from pathlib import Path

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTEXT_PATH = os.path.join(BASE_DIR, "tools", "input_context.json")

STATUS_COLORS = {
    "Tested": "#d4edda",
    "Audit": "#fff3cd",
    "Pending": "#f8d7da"
}

TACTICS_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact"
]

def normalize(t):
    return t.strip().lower().replace("_", "-").replace(" ", "-")

def load_context():
    with open(CONTEXT_PATH, encoding="utf-8") as f:
        return json.load(f)

def load_status_rows(csv_path):
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def main():
    context = load_context()
    apt_name = context["apt_name"] if context.get("apt_mode") else "SingleTechnique"
    csv_path = os.path.join(BASE_DIR, "mapping", apt_name, "status.csv")
    html_path = os.path.join(BASE_DIR, "report", apt_name, "index.html")

    if not os.path.exists(csv_path) or not os.path.exists(html_path):
        print("[!] Brak pliku CSV lub HTML.")
        return

    rows = load_status_rows(csv_path)
    matrix = {t: [] for t in TACTICS_ORDER}
    for r in rows:
        for t in r['Tactics'].split(','):
            key = t.strip().lower()
            if key in matrix:
                bg = STATUS_COLORS.get(r['Status'], '#ffffff')
                cell = f"<td style='background:{bg};'>{r['Technique ID']}<br>{r['Name']}<br>[{r['Status']}]</td>"
                matrix[key].append(cell)

    section = [
        '<hr>',
        '<h2>🧭 Macierz ATT&CK – tabela logiczna</h2>',
        '<table border="1" cellspacing="0" cellpadding="6"><tr>' +
        ''.join(f'<th>{t}</th>' for t in TACTICS_ORDER) +
        '</tr><tr>' +
        ''.join(matrix[t][0] if matrix[t] else '<td></td>' for t in TACTICS_ORDER) +
        '</tr></table>'
    ]
    with open(html_path, 'a', encoding='utf-8') as f:
        f.write('\n'.join(section))

    print(f"[✓] Macierz ATT&CK – tabela logiczna dodana do {html_path}")

if __name__ == "__main__":
    main()
