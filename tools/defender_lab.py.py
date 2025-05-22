import os
import csv
import json
from datetime import datetime
from collections import defaultdict, Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAPPING_DIR = os.path.join(BASE, "mapping")
REPORT_DIR = os.path.join(BASE, "report")
TOOLS_DIR = os.path.join(BASE, "tools")
ALERTS_DIR = os.path.join(BASE, "alerts")
HUNTING_DIR = os.path.join(BASE, "hunting")
SCENARIOS_DIR = os.path.join(BASE, "scenarios")
ATTACK_DB = os.path.join(TOOLS_DIR, "enterprise_attack.csv")

os.makedirs(MAPPING_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(ALERTS_DIR, exist_ok=True)
os.makedirs(HUNTING_DIR, exist_ok=True)
os.makedirs(SCENARIOS_DIR, exist_ok=True)

TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
]
TACTIC_TO_NICE = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}
STATUS_COLORS = {
    "Tested": "badge-Tested",
    "Audit": "badge-Audit",
    "Pending": "badge-Pending"
}
STATUS_NAV_COLORS = {
    "Tested": "#40c057",
    "Audit": "#ffd43b",
    "Pending": "#ff6b6b"
}
ALLOWED_STATUSES = {"tested": "Tested", "audit": "Audit", "pending": "Pending"}

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

def write_alert_md(apt_name, tid, tname, tactics, status, alert_name):
    if not alert_name.endswith('.md'):
        alert_name += ".md"
    alerts_folder = os.path.join(ALERTS_DIR, apt_name)
    os.makedirs(alerts_folder, exist_ok=True)
    alert_path = os.path.join(alerts_folder, alert_name)
    stopka = f"""<!--
Tactics: {tactics}
Technique ID: {tid}
Technique Name: {tname}
Status: {status}
-->"""
    content = f"# Alert: {tname}\n\nOpis scenariusza lub detekcji.\n\n{stopka}\n"
    with open(alert_path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.relpath(alert_path, BASE).replace("\\", "/")

def write_hunting_kql(apt_name, tid, tname):
    hunting_folder = os.path.join(HUNTING_DIR, apt_name)
    os.makedirs(hunting_folder, exist_ok=True)
    kql_file = os.path.join(hunting_folder, f"{tid}.kql")
    placeholder = f"// Example hunting KQL for {tid} – {tname}\n// Uzupełnij query ręcznie\n"
    if not os.path.exists(kql_file):
        with open(kql_file, "w", encoding="utf-8") as f:
            f.write(placeholder)
    return os.path.relpath(kql_file, BASE).replace("\\", "/")

def write_scenario_md(apt_name, tid, tname, tactics, status):
    scenario_folder = os.path.join(SCENARIOS_DIR, apt_name)
    os.makedirs(scenario_folder, exist_ok=True)
    scenario_path = os.path.join(scenario_folder, f"{tid}.md")
    content = f"# Scenario: {tname}\n\nTechnika: {tid}\nTactics: {tactics}\nStatus: {status}\n"
    with open(scenario_path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.relpath(scenario_path, BASE).replace("\\", "/")

def update_scenarios_tags(apt_name, techs):
    scenario_folder = os.path.join(SCENARIOS_DIR, apt_name)
    tags_path = os.path.join(scenario_folder, "tags.json")
    tags = []
    for tech in techs:
        tags.append({
            "Technique ID": tech["Technique ID"],
            "Name": tech["Name"],
            "Tactics": tech["Tactics"],
            "Status": tech["Status"]
        })
    with open(tags_path, "w", encoding="utf-8") as f:
        json.dump(tags, f, indent=2)

def write_layer_json(apt_name, status_rows):
    techniques = []
    for row in status_rows:
        for tid in row['Technique ID'].split(','):
            techniques.append({
                "techniqueID": tid.strip(),
                "color": STATUS_NAV_COLORS.get(row['Status'], "#cccccc"),
                "comment": row["Name"] + f" ({row['Status']})"
            })
    layer = {
        "name": f"MITRE ATT&CK – {apt_name}",
        "version": "4.6",
        "domain": "enterprise-attack",
        "description": f"Wygenerowano {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "techniques": techniques,
        "gradient": {"colors": ["#fff2cc", "#ffb366"], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Tested", "color": STATUS_NAV_COLORS["Tested"]},
            {"label": "Audit", "color": STATUS_NAV_COLORS["Audit"]},
            {"label": "Pending", "color": STATUS_NAV_COLORS["Pending"]}
        ],
        "showTacticRowBackground": True,
        "showTacticColumnHeader": True,
        "layout": "side"
    }
    mapping_folder = os.path.join(MAPPING_DIR, apt_name)
    os.makedirs(mapping_folder, exist_ok=True)
    layer_path = os.path.join(mapping_folder, "layer.json")
    with open(layer_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return layer_path

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
    # Dodany JS do filtrowania checkboxów
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
    .filter-bar {{
      margin: 18px 0 14px 0;
    }}
    .filter-bar label {{
      font-size: 1.03em; margin-right: 12px; font-weight: 500;
    }}
    .filter-bar input[type=checkbox] {{ margin-right: 4px; }}
    @media print {{
      .legend, .filter-bar {{ display: none; }}
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
  <div class="filter-bar">
    <label><input type="checkbox" checked onchange="filterStatus('Tested')">Tested</label>
    <label><input type="checkbox" checked onchange="filterStatus('Audit')">Audit</label>
    <label><input type="checkbox" checked onchange="filterStatus('Pending')">Pending</label>
    <span style="margin-left:30px; color:#668; font-size:0.98em;">(Odznacz, aby ukryć wybrany status)</span>
  </div>
  <h1>🛡️ Defender Lab Framework –  macierz MITRE ATT&CK </h1>
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
      <td><a href='/{row['Linked Rule']}' target='_blank'>{os.path.basename(row['Linked Rule']) if row['Linked Rule'] else ''}</a></td>
    </tr>
"""
    html += """  </table>
</div>
<script>
function filterStatus(status) {
  const checkboxes = document.querySelectorAll('.filter-bar input[type=checkbox]');
  const showStatus = {};
  checkboxes.forEach(cb => { showStatus[cb.nextSibling.textContent.trim()] = cb.checked; });
  document.querySelectorAll('.matrix-technique').forEach(el => {
    const st = el.getAttribute('data-status');
    el.style.display = showStatus[st] ? '' : 'none';
  });
}
</script>
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
        write_layer_json(folder, rows)

def choose_or_create_folder(base_name):
    # Pokazuje istniejące foldery i pozwala wybrać lub utworzyć nowy
    existing = sorted([d for d in os.listdir(MAPPING_DIR) if os.path.isdir(os.path.join(MAPPING_DIR, d))])
    print(f"Dostępne foldery: {', '.join(existing) if existing else '[Brak – utworzysz nowy]'}")
    name = input(f"Podaj nazwę nowego folderu dla grupy APT lub wybierz istniejący folder (np. {base_name}): ").strip()
    return name if name else base_name

def main():
    print_banner()
    print("1. APT Mode (utworzy osobny folder dla adwersarza)\n2. SingleMode (sumuje dodawane techniki na jednej matrycy mitre)\n3. Masowa aktualizacja – odśwież statusy i raporty dla wszystkich folderów")
    mode = input("Twój wybór [1/2/3]: ").strip()
    attack_db = read_attack_db()
    if mode == "3":
        update_all_folders()
        return
    if mode == "2":
        apt_name = choose_or_create_folder("SingleTechnique")
    else:
        apt_name = choose_or_create_folder("APT")
    rows = read_status_csv(os.path.join(MAPPING_DIR, apt_name, "status.csv"))
    techs = []
    while True:
        tid = input("Podaj ID techniki (np. T1059): ").strip().upper()
        if tid not in attack_db:
            print(f"❗ Nie znaleziono techniki w enterprise_attack.csv. Spróbuj ponownie.")
            continue
        tname = attack_db[tid]["name"]
        tactics = ", ".join(attack_db[tid]["tactics"])
        # Idiotoodporność statusu
        status_raw = input("Podaj status (Pending/Audit/Tested): ").strip().lower()
        status = ALLOWED_STATUSES.get(status_raw, None)
        while not status:
            print("Dozwolone wartości: Pending, Audit, Tested.")
            status_raw = input("Podaj status (Pending/Audit/Tested): ").strip().lower()
            status = ALLOWED_STATUSES.get(status_raw, None)
        default_alert_name = f"{tid}_alert.md"
        alert_name = input(f"Podaj nazwę pliku dla tworzonego alertu (domyślnie {default_alert_name}): ").strip() or default_alert_name
        linked_rule_path = write_alert_md(apt_name, tid, tname, tactics, status, alert_name)
        write_hunting_kql(apt_name, tid, tname)
        write_scenario_md(apt_name, tid, tname, tactics, status)
        techs.append({
            "Technique ID": tid,
            "Name": tname,
            "Tactics": tactics,
            "Status": status,
            "Linked Rule": linked_rule_path
        })
        if input("Czy dodać kolejną technikę? [T/n]: ").strip().lower() == "n":
            break
    rows += techs
    out_csv = os.path.join(MAPPING_DIR, apt_name, "status.csv")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=["Technique ID", "Name", "Tactics", "Status", "Linked Rule"])
        w.writeheader()
        for row in rows:
            w.writerow(row)
    update_scenarios_tags(apt_name, techs)
    print(f"[✓] {apt_name} – zapisano {len(rows)} rekordów do status.csv")
    output_path = os.path.join(REPORT_DIR, apt_name, "index.html")
    generate_html_matrix(rows, apt_name, output_path)
    write_layer_json(apt_name, rows)
    print_banner()

if __name__ == "__main__":
    main()
