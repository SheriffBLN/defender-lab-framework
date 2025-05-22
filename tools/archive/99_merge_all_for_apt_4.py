import os
import csv
import json
from datetime import datetime
from collections import defaultdict, Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAPPING_DIR = os.path.join(BASE, "mapping")
REPORT_DIR = os.path.join(BASE, "report")
TOOLS_DIR = os.path.join(BASE, "tools")
ATTACK_DB = os.path.join(TOOLS_DIR, "enterprise_attack.csv")

os.makedirs(MAPPING_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
]
STATUS_COLORS = {
    "Tested": "badge-Tested",
    "Audit": "badge-Audit",
    "Pending": "badge-Pending"
}
STATUS_LABELS = {"Tested": "Tested", "Audit": "Audit", "Pending": "Pending"}

def print_banner():
    print("\n" + "="*70)
    print("🛡️ DEFENDER LAB FRAMEWORK – TRYB WEJŚCIOWY 🛡️".center(70))
    print("="*70 + "\n")

def read_attack_db():
    if not os.path.exists(ATTACK_DB):
        raise FileNotFoundError(f"Brak pliku {ATTACK_DB}.")
    data = {}
    with open(ATTACK_DB, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            data[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    return data

def read_status_csv(csv_path):
    if not os.path.exists(csv_path):
        return []
    with open(csv_path, encoding='utf-8') as f:
        return list(csv.DictReader(f))

def generate_html_matrix(status_rows, apt_name, output_path):
    status_count = Counter(row["Status"] for row in status_rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    matrix = defaultdict(list)
    for row in status_rows:
        for tactic in row["Tactics"].split(","):
            tactic = tactic.strip().lower()
            if tactic in TACTICS:
                matrix[tactic].append(row)
    total = len(status_rows)
    tested = status_count.get("Tested", 0)
    audit = status_count.get("Audit", 0)
    pending = status_count.get("Pending", 0)
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Defender Lab Framework – macierz MITRE ATT&CK</title>
  <style>
    body {{
      font-family: 'Segoe UI', Arial, sans-serif; background: #f7fafd; color: #23293b; margin: 0; padding: 0;
    }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}
    h1 {{ color: #14247a; margin-top: 0; font-size:2.1em; }}
    .matrix-table {{
      width: 100%; border-collapse: collapse; background: #f5f8ff; font-size: 1.05em;
    }}
    .matrix-table th, .matrix-table td {{
      border: 1px solid #dde3ef; padding: 11px 7px; text-align: left; min-width: 140px;
    }}
    .matrix-table th {{
      background: #eaf0fa; color: #222b44; font-size: 1.09em; font-weight: 600; letter-spacing: 0.01em;
      position: sticky; top: 49px; z-index: 2;
    }}
    .matrix-table td {{
      background: #f9fbfd; vertical-align: top; min-width: 140px;
    }}
    .matrix-technique {{
      margin-bottom: 10px; padding: 10px 8px 10px 14px; border-radius: 7px; border: 1.2px solid #e5e9f2;
      background: #fff; box-shadow: 0 1.5px 7px #dde3ef33; position: relative; transition: box-shadow 0.13s;
    }}
    .matrix-technique:hover {{
      box-shadow: 0 2px 13px #8cc2ff33; border-color: #b3d3ff;
    }}
    .matrix-technique b {{ font-size: 1.01em; color: #14247a; letter-spacing: 0.3px; }}
    .badge {{
      display: inline-block; padding: 3px 11px; border-radius: 6px; font-size: 0.93em; color: #fff; font-weight: 500;
      margin-right: 3px; margin-top: 2px; margin-bottom: 3px;
    }}
    .badge-Tested {{ background: #40c057; }}
    .badge-Audit {{ background: #ffd43b; color: #222; }}
    .badge-Pending {{ background: #ff6b6b; }}
    .icon-status {{
      width: 19px; height: 19px; vertical-align: middle; margin-right: 2px; margin-bottom: 2px;
    }}
    .legend {{
      position: sticky; top: 0; background: #f3f6fb; z-index: 10;
      padding: 11px 0 5px 0; border-bottom: 2px solid #dde3ef; margin-bottom: 18px;
      display: flex; align-items: center; gap: 16px;
    }}
    .legend span {{ font-size: 1.04em; margin-right: 6px; }}
    .legend .legend-badge {{ margin-right: 22px; }}
    .tactic-icon {{
      width: 17px; height: 17px; vertical-align: text-bottom; margin-right: 4px; opacity: 0.82;
    }}
    .tactic-header {{
      display: flex; align-items: center; gap: 5px;
    }}
    @media print {{
      .legend {{ display: none; }}
      .matrix-table th, .matrix-table td {{ font-size: 0.89em; }}
    }}
    .table-status {{
      width: 98%; border-collapse: collapse; margin: 38px 0 12px 0; background: #f5f8ff;
    }}
    .table-status th, .table-status td {{
      border: 1px solid #dde3ef; padding: 9px 6px; text-align: left; min-width: 120px; font-size: 1.01em;
    }}
    .table-status th {{ background: #eaf0fa; font-weight: 600; }}
    .table-status td {{ background: #fff; }}
  </style>
</head>
<body>
<div class="container">
  <div class="legend">
    <span><b>Status:</b></span>
    <span class="legend-badge badge badge-Tested"><img class="icon-status" src="data:image/svg+xml;utf8,<svg fill='white' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='10' fill='%2340c057'/><path d='M8 12l2 2l4-4' stroke='white' stroke-width='2' fill='none'/></svg>">Tested</span>
    <span class="legend-badge badge badge-Audit"><img class="icon-status" src="data:image/svg+xml;utf8,<svg fill='black' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='10' fill='%23ffd43b'/><path d='M12 8v4m0 4h.01' stroke='black' stroke-width='2' fill='none'/></svg>">Audit</span>
    <span class="legend-badge badge badge-Pending"><img class="icon-status" src="data:image/svg+xml;utf8,<svg fill='white' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='10' fill='%23ff6b6b'/><path d='M8 8l8 8M8 16L16 8' stroke='white' stroke-width='2' fill='none'/></svg>">Pending</span>
    <button onclick="window.print()" style="margin-left:25px; padding: 3px 12px; border-radius:5px; border: none; background:#1765ce; color:#fff; font-size:1em;">🖨️ Drukuj / PDF</button>
  </div>

  <h1>🛡️ Defender Lab Framework – macierz MITRE ATT&CK </h1>
  <div style="font-size:1.09em;margin-bottom:8px;">Wygenerowano: {now} | <b>Liczba technik:</b> {total} (<span class='badge badge-Tested'>Tested</span>: {tested}, <span class='badge badge-Audit'>Audit</span>: {audit}, <span class='badge badge-Pending'>Pending</span>: {pending})</div>
  <h2>🧭 Macierz ATT&CK – tabela logiczna</h2>
  <table class="matrix-table" id="matrix">
    <tr>
      <th><span class="tactic-header"><img class="tactic-icon" src="https://img.icons8.com/color/48/000000/lock.png"/>initial-access</span></th>
      <th><span class="tactic-header"><img class="tactic-icon" src="https://img.icons8.com/color/48/000000/play.png"/>execution</span></th>
      <th><span class="tactic-header"><img class="tactic-icon" src="https://img.icons8.com/color/48/000000/time-machine.png"/>persistence</span></th>
      <th><span class="tactic-header"><img class="tactic-icon" src="https://img.icons8.com/color/48/000000/top-menu-bar.png"/>privilege-escalation</span></th>
      <th><span class="tactic-header"><img class="tactic-icon" src="https://img.icons8.com/color/48/000000/erase.png"/>defense-evasion</span></th>
      <th>credential-access</th>
      <th>discovery</th>
      <th>lateral-movement</th>
      <th>collection</th>
      <th>command-and-control</th>
      <th>exfiltration</th>
      <th>impact</th>
    </tr>
    <tr>
"""
    for tactic in TACTICS:
        html += "      <td>\n"
        for row in matrix.get(tactic, []):
            html += f"""        <div class="matrix-technique {STATUS_COLORS.get(row['Status'], '')}" data-status="{row['Status']}">
          <b>{row['Technique ID']}</b> {row['Name']}
          <span class="badge {STATUS_COLORS.get(row['Status'],'')}">{row['Status']}</span>
        </div>
"""
        html += "      </td>\n"
    html += """    </tr>
  </table>
  <h2 style="margin-top:38px;">📋 Tabela statusów z status.csv</h2>
  <table class="table-status">
    <tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Linked Rule</th></tr>
"""
    for row in status_rows:
        html += f"""    <tr>
      <td>{row['Technique ID']}</td>
      <td>{row['Name']}</td>
      <td>{row['Tactics']}</td>
      <td><span class="badge {STATUS_COLORS.get(row['Status'],'')}">{row['Status']}</span></td>
      <td>{row['Linked Rule']}</td>
    </tr>
"""
    html += """  </table>
</div>
</body>
</html>
"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] Raport HTML wygenerowany do: {output_path}")

def update_all_folders():
    print("\n[Masowa aktualizacja statusów i raportów]")
    print("Edytuj status.csv w wybranym folderze (mapping/NAZWAFOLDERU/status.csv), a potem użyj tej opcji by odświeżyć raporty.")
    for folder in os.listdir(MAPPING_DIR):
        path = os.path.join(MAPPING_DIR, folder, "status.csv")
        if not os.path.exists(path):
            continue
        rows = read_status_csv(path)
        output_path = os.path.join(REPORT_DIR, folder, "index.html")
        generate_html_matrix(rows, folder, output_path)

def main():
    print_banner()
    print("1. APT (osobny folder)\n2. SingleTechnique (sumuje)\n3. Masowy update – odśwież statusy i raporty dla wszystkich folderów")
    mode = ""
    while mode not in {"1", "2", "3"}:
        mode = input("Twój wybór [1/2/3]: ").strip()
    if mode == "3":
        update_all_folders()
        print_banner()
        return

    attack_db = read_attack_db()
    existing = [f for f in os.listdir(MAPPING_DIR) if os.path.isdir(os.path.join(MAPPING_DIR, f))]
    if existing:
        print("Dostępne foldery APT/SingleTechnique: ", ", ".join(existing))
    apt_name = input("Podaj nazwę grupy APT lub 'SingleTechnique': ").strip() or "SingleTechnique"
    csv_path = os.path.join(MAPPING_DIR, apt_name, "status.csv")
    if os.path.exists(csv_path) and input("Status.csv już istnieje. Dodać kolejne techniki? [T/n]: ").strip().lower() != "n":
        rows = read_status_csv(csv_path)
    else:
        rows = []
    techs = []
    while True:
        tid = input("Podaj ID techniki (np. T1059): ").strip().upper()
        if not tid:
            break
        if tid not in attack_db:
            print("❗ Nie znaleziono techniki w enterprise_attack.csv. Spróbuj ponownie.")
            continue
        tinfo = attack_db[tid]
        tname = tinfo["name"]
        tactics = ", ".join(tinfo["tactics"])
        status = ""
        while status not in STATUS_LABELS:
            status = input("Podaj status (Pending/Audit/Tested): ").strip().capitalize()
        techs.append({
            "Technique ID": tid,
            "Name": tname,
            "Tactics": tactics,
            "Status": status,
            "Linked Rule": ""
        })
        if input("Dodać kolejną technikę? [T/n]: ").strip().lower() == "n":
            break
    rows += techs
    out_csv = os.path.join(MAPPING_DIR, apt_name, "status.csv")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=["Technique ID", "Name", "Tactics", "Status", "Linked Rule"])
        w.writeheader()
        for row in rows:
            w.writerow(row)
    print(f"[✓] {apt_name} – zapisano {len(rows)} rekordów do status.csv")
    output_path = os.path.join(REPORT_DIR, apt_name, "index.html")
    generate_html_matrix(rows, apt_name, output_path)
    print_banner()

if __name__ == "__main__":
    main()
