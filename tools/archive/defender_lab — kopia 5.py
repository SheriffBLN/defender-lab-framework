import os
import json
import csv
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path

# --- USTAWIENIA KOLORÓW HEATMAPY ---
HEATMAP_COLORS = [
    (1, "#ffffb3"),
    (2, "#ffd480"),
    (3, "#ffa366"),
    (4, "#ff704d"),
    (5, "#c653ff"),
    (10, "#6f42c1")
]
DEFAULT_HEATMAP_COLOR = "#e9ecef"

STATUS_COLORS = {
    "Tested": "#40c057",
    "Audit": "#ffd43b",
    "Pending": "#ff6b6b"
}

STATUS_BG_COLORS = {   # Dla kafelków macierzy
    "Tested": "#e9fbe8",
    "Audit": "#fffbe8",
    "Pending": "#ffeaea"
}

TACTICS_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact"
]

def print_banner():
    print("\n")
    print("🛡️" * 5)
    print("      🛡️ DEFENDER-LAB-FRAMEWORK 🛡️")
    print("        Tryb wejściowy")
    print("🛡️" * 5 + "\n")

def choose_mode():
    print("=== Wybierz tryb pracy ===")
    print("1) SingleTechnique (sumowane globalnie)")
    print("2) APT Group (oddzielna matryca)")
    print("3) Update (masowa aktualizacja raportów)")
    while True:
        try:
            mode = int(input("Wybierz tryb (1/2/3): "))
            if mode in [1,2,3]:
                return mode
        except ValueError:
            pass
        print("Podaj poprawną wartość (1/2/3)")

def load_enterprise_techniques():
    data = {}
    with open("tools/enterprise_attack.csv", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            data[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    return data

def ask_for_technique(techniques_db):
    while True:
        tid = input("Podaj ID techniki (np. T1059): ").strip().upper()
        if tid in techniques_db:
            return tid
        print("Nieprawidłowy ID techniki! Dostępne: np. " + ', '.join(list(techniques_db.keys())[:10]))

def ask_status():
    while True:
        status = input("Podaj status (Pending/Audit/Tested): ").strip().capitalize()
        if status in ["Pending", "Audit", "Tested"]:
            return status
        print("Status musi być jednym z: Pending, Audit, Tested")

def ask_alert_name():
    alert_name = input("Podaj nazwę dla alertu (np. Suspicious_PS_Exec): ").strip()
    if not alert_name:
        alert_name = "alert"
    return alert_name

def generate_alert_md(technique_id, technique_name, tactics, status, author, alert_name, apt_folder):
    content = f"""# Alert: {technique_name}

Opis scenariusza, podatności lub techniki.

---

**Technika:** {technique_id}  
**Nazwa:** {technique_name}  
**Taktyki:** {', '.join(tactics)}  
**Status:** {status}  
**Autor:** {author}  

---

<!--
Tactics: {', '.join(tactics)}
Technique ID: {technique_id}
Technique Name: {technique_name}
Status: {status}
--> 
"""
    alert_folder = os.path.join("alerts", apt_folder)
    os.makedirs(alert_folder, exist_ok=True)
    md_path = os.path.join(alert_folder, f"{alert_name}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(content)
    return md_path

def generate_scenario_md_and_tags(technique_id, technique_name, tactics, status, author, alert_md_rel, apt_folder):
    scenario_folder = os.path.join("scenarios", apt_folder, technique_id)
    os.makedirs(scenario_folder, exist_ok=True)
    scenario_content = f"""# Scenariusz testowy – {technique_id}

## Symulacja ataku

Opis: Tutaj wpisz jak zasymulować technikę {technique_id} – {technique_name}.

## Detekcja

Oczekiwany alert: `{alert_md_rel}`

## Oczekiwany efekt

Technika powinna zostać wykryta w systemie M365 Defender. Taktyki: {', '.join(tactics)}.

**Status testu:** {status}
**Autor:** {author}
"""
    scenario_md_path = os.path.join(scenario_folder, f"{technique_id}_scenario.md")
    with open(scenario_md_path, "w", encoding="utf-8") as f:
        f.write(scenario_content)
    tag_data = {
        "id": technique_id,
        "name": technique_name,
        "tactics": tactics,
        "status": status,
        "linked_rule": alert_md_rel,
        "author": author
    }
    tags_path = os.path.join(scenario_folder, "tags.json")
    with open(tags_path, "w", encoding="utf-8") as f:
        json.dump(tag_data, f, indent=4, ensure_ascii=False)

def generate_layer_json(techniques, apt_folder):
    techniques_json = [{"techniqueID": tid, "score": 1} for tid in techniques]
    layer = {
        "name": f"{apt_folder} – Lab Coverage",
        "version": "4.6",
        "domain": "enterprise-attack",
        "techniques": techniques_json,
    }
    layer_path = os.path.join("mapping", apt_folder, "layer.json")
    os.makedirs(os.path.dirname(layer_path), exist_ok=True)
    with open(layer_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=4)
    return layer_path

def generate_status_csv(techniques, apt_folder):
    rows = []
    for tech in techniques:
        scenario_folder = os.path.join("scenarios", apt_folder, tech["technique_id"])
        tags_file = os.path.join(scenario_folder, "tags.json")
        if not os.path.exists(tags_file):
            continue
        with open(tags_file, encoding="utf-8") as f:
            tag = json.load(f)
            rows.append([
                tag.get('id',''),
                tag.get('name',''),
                ", ".join(tag.get('tactics',[])),
                tag.get('status',''),
                tag.get('linked_rule',''),
                tag.get('author','')
            ])
    out_csv = os.path.join("mapping", apt_folder, "status.csv")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Technique ID", "Name", "Tactics", "Status", "Linked Rule", "Author"])
        writer.writerows(rows)
    return out_csv

def parse_status_csv(status_csv_path):
    rows = []
    if not os.path.exists(status_csv_path):
        return []
    with open(status_csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def get_heatmap_color(cnt):
    if cnt >= 10:
        return "#6f42c1"
    if cnt >= 5:
        return "#c653ff"
    if cnt >= 4:
        return "#ff704d"
    if cnt >= 3:
        return "#ffa366"
    if cnt >= 2:
        return "#ffd480"
    if cnt == 1:
        return "#ffffb3"
    return DEFAULT_HEATMAP_COLOR

def generate_heatmap_section(apt_folder, techniques_db):
    csv_path = "tools/helpers/last30days_alerts.csv"
    if not os.path.exists(csv_path):
        return "<h2>Heatmapa aktywności</h2><p><i>Brak pliku z alertami Defendera (<code>last30days_alerts.csv</code>).</i></p>"
    alerts = []
    try:
        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                alerts.append(row)
    except Exception as e:
        return f"<h2>Heatmapa aktywności</h2><p>Błąd wczytywania pliku alertów: {e}</p>"
    if not alerts or "Technique ID" not in alerts[0] or "Count" not in alerts[0]:
        return "<h2>Heatmapa aktywności</h2><p><i>Brak danych do wygenerowania heatmapy.</i></p>"
    counts = {row["Technique ID"].strip().upper(): int(row["Count"]) for row in alerts if row["Technique ID"].strip()}

    # FILTRUJEMY po technikach danej grupy APT!
    folder = apt_folder
    # Jeśli SingleTechnique – wyświetl wszystkie techniki
    if folder == "SingleTechnique":
        allowed_tids = set(counts.keys())
    else:
        # Dla APT – tylko te techniki, które są w status.csv tej grupy!
        status_path = os.path.join("mapping", folder, "status.csv")
        group_rows = parse_status_csv(status_path)
        allowed_tids = set(r["Technique ID"].strip().upper() for r in group_rows)

    # Mapowanie: technika -> (nazwa, taktyki)
    tactic_map = {tac: [] for tac in TACTICS_ORDER}
    for tid, count in counts.items():
        if tid not in allowed_tids:
            continue
        entry = techniques_db.get(tid, None)
        if entry:
            for tac in entry["tactics"]:
                tac = tac.strip().lower()
                if tac in tactic_map:
                    tactic_map[tac].append((tid, entry.get("name", ""), count))
    html = []
    html.append('<h2 style="margin-top:42px;">🔥 Heatmapa aktywności z Defendera (ostatnie 30 dni)</h2>')
    html.append('''
    <style>
    .heatmap-matrix-table {
        border-collapse: separate;
        border-spacing: 6px 2px;
        width: 100%;
        margin-bottom: 32px;
    }
    .heatmap-matrix-table th {
        background: #f7faff;
        font-size: 1.15em;
        padding: 10px 0 6px 0;
        text-align: center;
        border-bottom: 2px solid #d8e6fa;
    }
    .heatmap-cell {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-width: 120px;
        min-height: 68px;
        margin: 0 auto;
        font-size: 1.06em;
        border-radius: 12px;
        box-shadow: 0 2px 10px #ddd3;
        margin-bottom: 3px;
        margin-top: 3px;
        font-weight: 500;
        border: 1px solid #e8e9f0;
    }
    </style>
    <div style="overflow-x:auto;max-width:1200px;">
      <table class="heatmap-matrix-table">
        <tr>
    ''')
    for tactic in TACTICS_ORDER:
        html.append(f'<th>{tactic}</th>')
    html.append('</tr><tr>')
    for tactic in TACTICS_ORDER:
        cells = ""
        techs = tactic_map.get(tactic, [])
        if techs:
            for tid, name, count in sorted(techs, key=lambda x: -x[2]):
                color = get_heatmap_color(count)
                cells += (
                    f'<div class="heatmap-cell" style="background:{color}">'
                    f'<b>{name}</b><br><span style="font-size:0.96em;">{tid}</span><br>'
                    f'<span style="font-size:1.14em;font-weight:bold;">{count}</span></div>'
                )
        html.append(f'<td style="vertical-align:top;">{cells}</td>')
    html.append('</tr></table></div>')
    return "\n".join(html)

def generate_html_report(apt_folder, status_csv_path, techniques_db):
    rows = parse_status_csv(status_csv_path)
    output_path = os.path.join("report", apt_folder, "index.html")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    total = len(rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_counts = Counter(r["Status"] for r in rows)
    tactic_groups = defaultdict(list)
    for r in rows:
        for t in r["Tactics"].split(","):
            tac = t.strip()
            if tac:
                tactic_groups[tac].append(r)

    html = [
        '<!DOCTYPE html>', '<html>', '<head>', '  <meta charset="UTF-8">',
        f'  <title>🛡️ Defender Lab Framework – macierz MITRE ATT&CK</title>',
        '  <style>',
        "body { font-family:'Segoe UI',Arial,sans-serif;background:#f7fafd;color:#23293b;margin:0;padding:0; }",
        ".container { max-width:1400px;margin:0 auto;padding:30px; }",
        "h1 { color:#14247a; margin-top:0; }",
        ".matrix-table { width:100%; border-collapse:collapse; background:#f5f8ff; font-size:1.05em; }",
        ".matrix-table th, .matrix-table td { border:1px solid #dde3ef; padding:11px 7px; text-align:left; min-width:140px; }",
        ".matrix-table th { background:#eaf0fa; color:#222b44; font-size:1.09em; font-weight:600; letter-spacing:0.01em; position:sticky; top:49px; z-index:2; }",
        ".matrix-table td { background:#f9fbfd; vertical-align:top; min-width:140px; }",
        ".matrix-technique { margin-bottom:10px; padding:10px 8px 10px 14px; border-radius:7px; border:1.2px solid #e5e9f2; box-shadow:0 1.5px 7px #dde3ef33; position:relative; transition:box-shadow 0.13s; }",
        ".matrix-technique:hover { box-shadow:0 2px 13px #8cc2ff33; border-color:#b3d3ff; }",
        ".matrix-technique b { font-size:1.01em; color:#14247a; letter-spacing:0.3px; }",
        ".badge { display:inline-block; padding:3px 11px; border-radius:6px; font-size:0.93em; color:#fff; font-weight:500; margin-right:3px; margin-top:2px; margin-bottom:3px; }",
        ".badge-Tested { background:#40c057; } .badge-Audit { background:#ffd43b; color:#222; } .badge-Pending { background:#ff6b6b; }",
        ".matrix-technique.badge-Tested { background:#e9fbe8 !important; }",
        ".matrix-technique.badge-Audit { background:#fffbe8 !important; }",
        ".matrix-technique.badge-Pending { background:#ffeaea !important; }",
        ".legend { position:sticky; top:0; background:#f3f6fb; z-index:10; padding:11px 0 5px 0; border-bottom:2px solid #dde3ef; margin-bottom:18px; display:flex; align-items:center; gap:16px; }",
        ".legend span { font-size:1.04em; margin-right:6px; } .legend .legend-badge { margin-right:22px; }",
        ".tactic-header { display:flex; align-items:center; gap:5px; }",
        ".filter-bar { margin:18px 0 14px 0; } .filter-bar label { font-size:1.03em; margin-right:12px; font-weight:500; }",
        ".filter-bar input[type=checkbox] { margin-right:4px; }",
        ".status-table { margin-top:36px; margin-bottom:34px; border-collapse:collapse; min-width:600px; font-size:1.07em; background:#f7fafd; border:1.2px solid #dde3ef; box-shadow:0 2px 12px #dde3ef30; }",
        ".status-table th, .status-table td { border:1px solid #dde3ef; padding:9px 11px; text-align:left; }",
        ".status-table th { background:#eaf0fa; font-weight:600; color:#14247a; }",
        ".status-Tested { background:#e9fbe8; } .status-Audit { background:#fffbe8; } .status-Pending { background:#ffeaea; }",
        "@media print { .legend, .copy-btn, .filter-bar { display:none; } .matrix-table th, .matrix-table td { font-size:0.89em; } }",
        '</style>', '</head>', '<body>', '<div class="container">'
    ]
    html.append(
        '<div class="legend">'
        '<span><b>Status:</b></span>'
        '<span class="legend-badge badge badge-Tested">Tested</span>'
        '<span class="legend-badge badge badge-Audit">Audit</span>'
        '<span class="legend-badge badge badge-Pending">Pending</span>'
        '</div>'
    )
    if apt_folder != "SingleTechnique":
        html.append(f'<h1>🛡️ Defender Lab Framework – macierz MITRE ATT&CK <span style="font-weight:400;">dla grupy: <b style="color:#2563eb">{apt_folder}</b></span></h1>')
    else:
        html.append('<h1>🛡️ Defender Lab Framework – macierz MITRE ATT&CK </h1>')

    # Filtr statusów – checkboksy
    html.append(
        '''
        <div class="filter-bar">
          <label><input type="checkbox" checked onchange="filterStatus('Tested')">Tested</label>
          <label><input type="checkbox" checked onchange="filterStatus('Audit')">Audit</label>
          <label><input type="checkbox" checked onchange="filterStatus('Pending')">Pending</label>
          <span style="margin-left:30px; color:#668; font-size:0.98em;">(Odznacz, aby ukryć wybrany status)</span>
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
        '''
    )
    # Macierz logiczna (tabela taktyk)
    html.append('<h2>🧭 Macierz ATT&CK – tabela logiczna</h2>')
    html.append('<table class="matrix-table" id="matrix"><tr>')
    for tactic in TACTICS_ORDER:
        html.append(f'<th>{tactic}</th>')
    html.append('</tr><tr>')
    matrix = {t: [] for t in TACTICS_ORDER}
    for r in rows:
        for t in r["Tactics"].split(","):
            key = t.strip().lower()
            if key in matrix:
                badge = f'<span class="badge badge-{r["Status"]}">{r["Status"]}</span>'
                bgstyle = f'background:{STATUS_BG_COLORS.get(r["Status"], "#fff")};'
                cell = (
                    f'<div class="matrix-technique badge-{r["Status"]}" data-status="{r["Status"]}" style="{bgstyle}">'
                    f"<b>{r['Technique ID']}</b> {r['Name']}<br>{badge}"
                    f"</div>"
                )
                matrix[key].append(cell)
    for tactic in TACTICS_ORDER:
        html.append("<td>" + "".join(matrix[tactic]) + "</td>")
    html.append('</tr></table>')

    # --- SEKCJA: tabela statusów ---
    html.append('<h2>📋 Szczegóły statusów</h2>')
    html.append('<div style="overflow-x:auto;"><table class="status-table"><tr>')
    html.extend([
        "<th>ID</th><th>Nazwa</th><th>Taktyki</th><th>Status</th><th>Linked Rule</th><th>Autor</th>"
    ])
    html.append("</tr>")
    for r in rows:
        row_class = f"status-{r['Status']}"
        html.append(
            f'<tr class="{row_class}">'
            f'<td><b>{r["Technique ID"]}</b></td>'
            f'<td>{r["Name"]}</td>'
            f'<td>{r["Tactics"]}</td>'
            f'<td>{r["Status"]}</td>'
            f'<td>{r["Linked Rule"]}</td>'
            f'<td>{r["Author"]}</td>'
            "</tr>"
        )
    html.append("</table></div>")
    # --- SEKCJA: HEATMAPA ---
    html.append(generate_heatmap_section(apt_folder, techniques_db))
    html.append('</div></body></html>')
    Path(output_path).write_text("\n".join(html), encoding="utf-8")
    print(f"[✓] Raport HTML wygenerowany do: {output_path}")

def workflow():
    print_banner()
    mode = choose_mode()
    techniques_db = load_enterprise_techniques()
    # SingleTechnique (globalne)
    if mode == 1:
        apt_folder = "SingleTechnique"
        print(f"\n[SingleTechnique] - wszystkie techniki będą sumowane do wspólnej matrycy ({apt_folder})\n")
        techniques = []
        while True:
            tid = ask_for_technique(techniques_db)
            status = ask_status()
            author = input("Podaj autora (opcjonalnie): ").strip()
            alert_name = ask_alert_name()
            tech_data = techniques_db[tid]
            alert_md_rel = f"alerts/{apt_folder}/{alert_name}.md"
            generate_alert_md(tid, tech_data["name"], tech_data["tactics"], status, author, alert_name, apt_folder)
            generate_scenario_md_and_tags(tid, tech_data["name"], tech_data["tactics"], status, author, alert_md_rel, apt_folder)
            techniques.append({"technique_id": tid})
            generate_layer_json([t["technique_id"] for t in techniques], apt_folder)
            generate_status_csv(techniques, apt_folder)
            generate_html_report(apt_folder, os.path.join("mapping", apt_folder, "status.csv"), techniques_db)
            cont = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if cont != "t":
                break
    elif mode == 2:
        print("\nDostępne grupy APT (foldery):")
        apt_folders = [f for f in os.listdir("mapping") if os.path.isdir(os.path.join("mapping", f))]
        if apt_folders:
            print("Już istniejące:", ", ".join(apt_folders))
        apt_folder = input("Podaj nazwę grupy APT: ").strip()
        techniques = []
        while True:
            tid = ask_for_technique(techniques_db)
            status = ask_status()
            author = input("Podaj autora (opcjonalnie): ").strip()
            alert_name = ask_alert_name()
            tech_data = techniques_db[tid]
            alert_md_rel = f"alerts/{apt_folder}/{alert_name}.md"
            generate_alert_md(tid, tech_data["name"], tech_data["tactics"], status, author, alert_name, apt_folder)
            generate_scenario_md_and_tags(tid, tech_data["name"], tech_data["tactics"], status, author, alert_md_rel, apt_folder)
            techniques.append({"technique_id": tid})
            generate_layer_json([t["technique_id"] for t in techniques], apt_folder)
            generate_status_csv(techniques, apt_folder)
            generate_html_report(apt_folder, os.path.join("mapping", apt_folder, "status.csv"), techniques_db)
            cont = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if cont != "t":
                break
    elif mode == 3:
        print("\nTryb masowej aktualizacji: generowanie macierzy na podstawie status.csv.")
        print("W razie potrzeby edytuj mapping/NAZWA/status.csv, następnie uruchom update.")
        apt_folders = [f for f in os.listdir("mapping") if os.path.isdir(os.path.join("mapping", f))]
        if not apt_folders:
            print("Brak istniejących matryc do aktualizacji.")
            return
        print("Dostępne foldery matryc:", ", ".join(apt_folders))
        for apt_folder in apt_folders:
            status_csv_path = os.path.join("mapping", apt_folder, "status.csv")
            if os.path.exists(status_csv_path):
                generate_html_report(apt_folder, status_csv_path, techniques_db)
                print(f"[✓] Zaktualizowano matrycę {apt_folder}")
            else:
                print(f"[!] Brak status.csv w {apt_folder}, pomijam.")

if __name__ == "__main__":
    workflow()
