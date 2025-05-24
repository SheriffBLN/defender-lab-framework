import os
import json
import csv
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path

# --- USTAWIENIA KOLORÓW HEATMAPY ---
HEATMAP_COLORS = [
    (1, "#ffffb3"),   # Żółty
    (2, "#ffd480"),   # Jasny pomarańcz
    (3, "#ffa366"),   # Pomarańcz
    (4, "#ff704d"),   # Czerwony
    (5, "#c653ff"),   # Fioletowy
    (10, "#6f42c1")   # Głęboki fiolet (10+)
]
DEFAULT_HEATMAP_COLOR = "#e9ecef"

STATUS_COLORS = {
    "Tested": "#40c057",
    "Audit": "#ffd43b",
    "Pending": "#ff6b6b"
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
    # Główny markdown alertu
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
    # Dla JIRA/Confluence można generować HTML równolegle (opcjonalnie)
    return md_path

def generate_scenario_md_and_tags(technique_id, technique_name, tactics, status, author, alert_md_rel, apt_folder):
    scenario_folder = os.path.join("scenarios", apt_folder, technique_id)
    os.makedirs(scenario_folder, exist_ok=True)
    # Scenario markdown
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
    # tags.json
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
        return "#6f42c1" # fiolet
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
    # Wczytaj heatmapę z pliku CSV
    csv_path = os.path.join("tools", "helpers", "last30days_alerts.csv")
    alert_counts = {}
    if os.path.exists(csv_path):
        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get("Technique ID") or row.get("TechniqueID") or row.get("TechniqueId")
                cnt = int(row.get("Count", "1"))
                if tid:
                    alert_counts[tid.strip()] = cnt
    # Lista technik danej grupy (status.csv)
    if apt_folder != "SingleTechnique":
        allowed_tids = set()
        status_csv = os.path.join("mapping", apt_folder, "status.csv")
        if os.path.exists(status_csv):
            with open(status_csv, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    allowed_tids.add(row["Technique ID"].strip())
        alert_counts = {tid: c for tid, c in alert_counts.items() if tid in allowed_tids}
    if not alert_counts:
        return f"<h2 style='margin-top:32px;'>🔥 Heatmapa aktywności z Defendera (ostatnie 30 dni){'' if apt_folder=='SingleTechnique' else f' dla grupy: <b>{apt_folder}</b>'}</h2><div style='margin:12px 0 30px 0; color:#777; font-size:1.14em;'>Brak danych do wygenerowania heatmapy.</div>"
    # ... dalsza część funkcji jak masz (generuje tabelę lub matrycę)


    # Wczytaj Alerts
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

    # Zbuduj słownik: technika -> liczba alertów
    counts = {row["Technique ID"].strip().upper(): int(row["Count"]) for row in alerts if row["Technique ID"].strip()}

    if not counts:
        return "<h2>Heatmapa aktywności</h2><p><i>Brak danych do wygenerowania heatmapy.</i></p>"

    # Mapowanie: technika -> (nazwa, taktyki)
    tactic_map = {tac: [] for tac in TACTICS_ORDER}
    for tid, count in counts.items():
        entry = techniques_db.get(tid, None)
        if entry:
            for tac in entry["tactics"]:
                tac = tac.strip().lower()
                if tac in tactic_map:
                    tactic_map[tac].append((tid, entry.get("name", ""), count))

    # Generowanie macierzy heatmapy – jak klasyczna macierz ATT&CK, wyśrodkowane kafelki, padding, min-width
    html = []
    html.append(f'<h2 style="margin-top:42px;">🔥 Heatmapa aktywności z Defendera (ostatnie 30 dni) dla grupy: <b>{apt_folder}</b></h2>')
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
    # Nagłówki taktyk
    for tactic in TACTICS_ORDER:
        html.append(f'<th>{tactic}</th>')
    html.append('</tr><tr>')

    # Kafelki technik
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

def generate_html_report(apt_folder, techniques_db):
    # Informacje
    status_csv = os.path.join("mapping", apt_folder, "status.csv")
    rows = parse_status_csv(status_csv)
    if not rows:
        return None
    # Zbuduj mapowanie taktyk -> lista technik (po statusie)
    tactic_groups = {tac: [] for tac in TACTICS_ORDER}
    for row in rows:
        for tactic in row["Tactics"].split(','):
            tactic = tactic.strip().lower()
            if tactic in tactic_groups:
                tactic_groups[tactic].append(row)
    # Policz statusy
    status_counter = Counter([row["Status"] for row in rows])
    total = len(rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Nazwa grupy do wyświetlenia
    groupname = apt_folder

    # --- HTML ---
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset='UTF-8'>",
        f"  <title>🛡️ Defender Lab Framework – macierz MITRE ATT&CK ({groupname})</title>",
        "<style>",
        "body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7fafd; color: #23293b; margin: 0; padding: 0; }",
        ".container { max-width: 1440px; margin: 0 auto; padding: 34px 20px 36px 20px; }",
        ".legend { position: sticky; top: 0; background: #f3f6fb; z-index: 10; padding: 11px 0 5px 0; border-bottom: 2px solid #dde3ef; margin-bottom: 18px; display: flex; align-items: center; gap: 16px; }",
        ".legend span { font-size: 1.04em; margin-right: 6px; }",
        ".legend .legend-badge { margin-right: 22px; }",
        ".badge { display: inline-block; padding: 3px 11px; border-radius: 6px; font-size: 0.93em; color: #fff; font-weight: 500; margin-right: 3px; margin-top: 2px; margin-bottom: 3px; }",
        ".badge-Tested { background: #40c057; }",
        ".badge-Audit { background: #ffd43b; color: #222; }",
        ".badge-Pending { background: #ff6b6b; }",
        ".matrix-table { width: 100%; border-collapse: collapse; background: #f5f8ff; font-size: 1.05em; }",
        ".matrix-table th, .matrix-table td { border: 1px solid #dde3ef; padding: 11px 7px; text-align: left; min-width: 140px; }",
        ".matrix-table th { background: #eaf0fa; color: #222b44; font-size: 1.09em; font-weight: 600; letter-spacing: 0.01em; position: sticky; top: 49px; z-index: 2; }",
        ".matrix-table td { background: #f9fbfd; vertical-align: top; min-width: 140px; }",
        ".matrix-technique { margin-bottom: 10px; padding: 10px 8px 10px 14px; border-radius: 7px; border: 1.2px solid #e5e9f2; background: #fff; box-shadow: 0 1.5px 7px #dde3ef33; position: relative; transition: box-shadow 0.13s; }",
        ".matrix-technique:hover { box-shadow: 0 2px 13px #8cc2ff33; border-color: #b3d3ff; }",
        ".matrix-technique b { font-size: 1.01em; color: #14247a; letter-spacing: 0.3px; }",
        ".tactic-header { display: flex; align-items: center; gap: 5px; }",
        ".filter-bar { margin: 18px 0 14px 0; }",
        ".filter-bar label { font-size: 1.03em; margin-right: 12px; font-weight: 500; }",
        ".filter-bar input[type=checkbox] { margin-right: 4px; }",
        ".status-table { margin-top:30px; border-collapse:collapse; min-width:800px; width:100%; }",
        ".status-table th, .status-table td { border:1px solid #dde3ef; padding:8px 10px; font-size:1.03em; }",
        ".status-table th { background:#eaf0fa; color:#23293b; font-weight:600; }",
        ".status-table td { background:#fcfcfc; }",
        "@media print { .legend, .copy-btn, .filter-bar { display: none; } .matrix-table th, .matrix-table td { font-size: 0.89em; } }",
        "</style>",
        "<script>",
        "function filterStatus(status) {",
        "  const checkboxes = document.querySelectorAll('.filter-bar input[type=checkbox]');",
        "  const showStatus = {};",
        "  checkboxes.forEach(cb => { showStatus[cb.nextSibling.textContent.trim()] = cb.checked; });",
        "  document.querySelectorAll('.matrix-technique').forEach(el => {",
        "    const st = el.getAttribute('data-status');",
        "    el.style.display = showStatus[st] ? '' : 'none';",
        "  });",
        "}",
        "</script>",
        "</head>",
        "<body>",
        "<div class='container'>",
        f"<div class='legend'>"
        "<span><b>Status:</b></span>"
        "<span class='legend-badge badge badge-Tested'>Tested</span>"
        "<span class='legend-badge badge badge-Audit'>Audit</span>"
        "<span class='legend-badge badge badge-Pending'>Pending</span>"
        "<button onclick='window.print()' style='margin-left:25px; padding: 3px 12px; border-radius:5px; border: none; background:#1765ce; color:#fff; font-size:1em;'>🖨️ Drukuj / PDF</button>"
        "</div>",
        f"<h1>🛡️ Defender Lab Framework – macierz MITRE ATT&CK dla grupy: <span style='color:#2d55bb'>{groupname}</span></h1>",
        f"<p>Wygenerowano: <b>{now}</b> &nbsp; | &nbsp; <b>Liczba technik:</b> {total}</p>",
        "<div class='filter-bar'>"
        "<label><input type='checkbox' checked onchange=\"filterStatus('Tested')\">Tested</label>"
        "<label><input type='checkbox' checked onchange=\"filterStatus('Audit')\">Audit</label>"
        "<label><input type='checkbox' checked onchange=\"filterStatus('Pending')\">Pending</label>"
        "<span style='margin-left:30px; color:#668; font-size:0.98em;'>(Odznacz, aby ukryć wybrany status)</span>"
        "</div>",
        "<h2>🧭 Macierz ATT&CK – tabela logiczna</h2>",
        "<table class='matrix-table' id='matrix'><tr>"
    ]
    # Nagłówki taktyk
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    # Techniki w kolumnach
    for tactic in TACTICS_ORDER:
        group = tactic_groups.get(tactic, [])
        cell = ""
        for row in group:
            bg = STATUS_COLORS.get(row["Status"], "#ffffff")
            cell += (
                f"<div class='matrix-technique badge-{row['Status']}' data-status='{row['Status']}'>"
                f"<b>{row['Technique ID']}</b> {row['Name']}<br>"
                f"<span class='badge badge-{row['Status']}'>{row['Status']}</span>"
                "</div>"
            )
        html.append(f"<td style='vertical-align:top;'>{cell}</td>")
    html.append("</tr></table>")

    # --- Tabela statusów ---
    html.append("<h2 style='margin-top:35px;'>Szczegóły statusów (status.csv)</h2>")
    html.append("<div style='overflow-x:auto;max-width:1400px;'><table class='status-table'>")
    html.append("<tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Linked Rule</th><th>Author</th></tr>")
    for row in rows:
        bg = STATUS_COLORS.get(row["Status"], "#fcfcfc")
        html.append(
            f"<tr style='background:{bg};'>"
            f"<td>{row['Technique ID']}</td>"
            f"<td>{row['Name']}</td>"
            f"<td>{row['Tactics']}</td>"
            f"<td>{row['Status']}</td>"
            f"<td>{row['Linked Rule']}</td>"
            f"<td>{row['Author']}</td></tr>"
        )
    html.append("</table></div>")

    # --- Heatmapa Defendera ---
    html.append(generate_heatmap_section(apt_folder, techniques_db))

    html.append("</div></body></html>")
    report_path = os.path.join("report", apt_folder, "index.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"[✓] Raport HTML wygenerowany do: {report_path}")

def run_workflow():
    print_banner()
    mode = choose_mode()
    techniques_db = load_enterprise_techniques()
    if mode in [1,2]:
        if mode == 2:
            print("\n=== Tryb: Grupa APT ===")
            apt_folder = input("Podaj nazwę grupy APT (np. APT29): ").strip()
        else:
            print("\n=== Tryb: SingleTechnique ===")
            apt_folder = "SingleTechnique"
        # Jeśli folder już istnieje, pozwól dodać techniki
        existing = []
        base = os.path.join("scenarios", apt_folder)
        if os.path.isdir(base):
            existing = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
            if existing:
                print(f"[i] W folderze {apt_folder} są już techniki: {', '.join(existing)}")
        # Pętla – dodawaj kolejne techniki
        techniques = []
        while True:
            tid = ask_for_technique(techniques_db)
            status = ask_status()
            author = input("Podaj autora: ").strip()
            alert_name = ask_alert_name()
            tdata = techniques_db[tid]
            alert_md_path = generate_alert_md(
                tid, tdata["name"], tdata["tactics"], status, author, alert_name, apt_folder
            )
            # względna ścieżka do markdowna alertu
            rel_alert = os.path.relpath(alert_md_path, os.path.join("scenarios", apt_folder, tid))
            generate_scenario_md_and_tags(
                tid, tdata["name"], tdata["tactics"], status, author, rel_alert, apt_folder
            )
            techniques.append({
                "technique_id": tid,
                "technique_name": tdata["name"],
                "tactics": tdata["tactics"],
                "status": status,
                "author": author,
                "alert_name": alert_name
            })
            cont = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if cont != "t":
                break
        # Generowanie layer.json
        generate_layer_json([tech["technique_id"] for tech in techniques], apt_folder)
        # Generowanie status.csv
        generate_status_csv(techniques, apt_folder)
        # Raport HTML
        generate_html_report(apt_folder, techniques_db)
        print("[✓] Wszystko gotowe! Pliki wygenerowane.")
    elif mode == 3:
        print("\n=== Tryb: Update ===")
        # Przeglądaj wszystkie mapping/*/status.csv i generuj macierze/raporty na nowo
        mapping = os.path.join("mapping")
        techniques_db = load_enterprise_techniques()
        for apt_folder in os.listdir(mapping):
            path = os.path.join(mapping, apt_folder, "status.csv")
            if os.path.exists(path):
                print(f"[i] Aktualizuję {apt_folder}...")
                generate_html_report(apt_folder, techniques_db)
        print("[✓] Wszystkie raporty zaktualizowane na podstawie status.csv.")

if __name__ == "__main__":
    run_workflow()

