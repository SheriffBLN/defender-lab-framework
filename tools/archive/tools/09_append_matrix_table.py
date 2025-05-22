import csv
from pathlib import Path

CSV_PATH = "mapping/mitre-navigator/status.csv"
INDEX_PATH = "report/index.html"

TACTIC_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]

# Budujemy strukturę: {tactic: set(techniki)}
from collections import defaultdict
matrix = defaultdict(set)

with open(CSV_PATH, newline='', encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        tid = row["Technique ID"].strip()
        name = row["Name"].strip()
        status = row["Status"].strip()
        label = f"{tid}<br>{name}<br>[{status}]"
        tactics = [t.strip().lower().replace(" ", "-") for t in row["Tactics"].split(",")]
        for tactic in tactics:
            if tactic in TACTIC_ORDER:
                matrix[tactic].add(label)

# Tworzymy HTML tabeli
html = '<h2>🧭 Macierz ATT&CK – tabela logiczna</h2>\n'
html += '<div style="overflow-x:auto;border:1px solid #ccc;margin-top:20px;">\n'
html += '<table style="border-collapse:collapse;min-width:1200px;">\n<thead><tr>'
for t in TACTIC_ORDER:
    html += f'<th style="background:#f2f2f2;border:1px solid #ccc;padding:8px;">{t}</th>'
html += '</tr></thead><tbody>\n'

# Ustal maksymalną liczbę wierszy
max_rows = max(len(v) for v in matrix.values())

for i in range(max_rows):
    html += '<tr>'
    for tactic in TACTIC_ORDER:
        items = list(matrix[tactic])
        cell = items[i] if i < len(items) else ""
        html += f'<td style="border:1px solid #ccc;padding:8px;vertical-align:top;">{cell}</td>'
    html += '</tr>\n'
html += '</tbody></table>\n</div>'

# Wczytaj aktualny index.html i doklej
original = Path(INDEX_PATH).read_text(encoding="utf-8")
patched = original.rstrip() + "\n\n<!-- Macierz ATT&CK dodana automatycznie -->\n" + html
Path(INDEX_PATH).write_text(patched, encoding="utf-8")
print("[INFO] Tabela logiczna została dołączona do report/index.html")