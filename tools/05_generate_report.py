import csv
import os
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

INPUT_CSV = "mapping/mitre-navigator/status.csv"
OUTPUT_HTML = "report/index.html"

STATUS_COLORS = {
    "Tested": "#d4edda",
    "Audit": "#fff3cd",
    "Pending": "#f8d7da"
}

def load_csv_data():
    if not Path(INPUT_CSV).exists():
        print(f"[!] Brak pliku CSV: {INPUT_CSV}")
        return {}, Counter()

    data = defaultdict(list)
    status_counter = Counter()

    with open(INPUT_CSV, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = row.get("Status", "")
            status_counter[status] += 1
            for tactic in row.get("Tactics", "").split(","):
                tactic = tactic.strip()
                if tactic:
                    data[tactic].append(row)

    return dict(sorted(data.items())), status_counter

def generate_html(data, status_counter):
    os.makedirs(Path(OUTPUT_HTML).parent, exist_ok=True)
    total = sum(status_counter.values())
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for tactic, items in data.items():
        rows.append(f"<h2>{tactic}</h2>")
        rows.append("<table border='1' cellspacing='0' cellpadding='6'>")
        rows.append("<tr><th>Technique ID</th><th>Name</th><th>Status</th><th>Linked Rule</th></tr>")
        for row in items:
            bg = STATUS_COLORS.get(row["Status"], "#ffffff")
            rule = row.get("Linked Rule", "")
            rule_link = f"<a href='../{rule}' target='_blank'>{rule}</a>" if rule.endswith(".md") else rule
            rows.append(
                f"<tr style='background:{bg};'><td>{row['Technique ID']}</td><td>{row['Name']}</td><td>{row['Status']}</td><td>{rule_link}</td></tr>"
            )
        rows.append("</table><br>")

    status_html = "".join([
        f"<li>{k}: {v}</li>" for k, v in status_counter.items()
    ])

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Defender Lab Detection Report</title>
    <style>
        body {{ font-family: Arial; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #eee; }}
        td, th {{ padding: 6px; text-align: left; }}
        li {{ margin-bottom: 4px; }}
    </style>
</head>
<body>
    <h1>Defender Lab Detection Report</h1>
    <p>Wygenerowano: {now}</p>
    <p>Łączna liczba technik: {total}</p>
    <ul>{status_html}</ul>
    {''.join(rows)}
</body>
</html>"""

    Path(OUTPUT_HTML).write_text(html, encoding="utf-8")
    print(f"[✓] Raport zapisany do: {OUTPUT_HTML}")

if __name__ == "__main__":
    data, counter = load_csv_data()
    if data:
        generate_html(data, counter)
