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

def append_or_update_status_csv(apt_folder, new_row):
    """Dodaje (lub aktualizuje) technikę w status.csv, bez duplikatów."""
    status_path = os.path.join("mapping", apt_folder, "status.csv")
    os.makedirs(os.path.dirname(status_path), exist_ok=True)
    all_rows = []
    # Jeśli istnieje status.csv – wczytaj i usuń duplikaty po Technique ID + AlertName
    if os.path.exists(status_path):
        with open(status_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["Technique ID"] == new_row["Technique ID"] and row["Linked Rule"] == new_row["Linked Rule"]:
                    continue  # Duplikat – nadpisz poniżej
                all_rows.append(row)
    all_rows.append(new_row)
    with open(status_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Technique ID","Name","Tactics","Status","Linked Rule","Author"])
        writer.writeheader()
        writer.writerows(all_rows)

def generate_layer_json(apt_folder, techniques):
    """Warstwa Navigatora – pod apt_folder."""
    out = os.path.join("mapping", apt_folder, "layer.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    layer = {
        "name": f"{apt_folder} – Lab Coverage",
        "version": "4.6",
        "domain": "enterprise-attack",
        "techniques": [{"techniqueID": t["Technique ID"], "score": 1} for t in techniques]
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=4)

def parse_heatmap_data():
    """Zwraca dict: technique_id -> count, na podstawie last30days_alerts.csv"""
    path = "tools/helpers/last30days_alerts.csv"
    if not os.path.exists(path):
        return {}
    counts = Counter()
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row.get("Technique ID") or row.get("technique_id") or row.get("AttackTechniques") or ""
            if tid:
                counts[tid.strip().upper()] += int(row.get("Count", 1))
    return counts

def heatmap_color_for_count(cnt):
    for limit, color in HEATMAP_COLORS:
        if cnt <= limit:
            return color
    return HEATMAP_COLORS[-1][1]

def render_heatmap_section_for_matrix(matrix, apt_folder, only_techniques=None):
    """Generuje sekcję heatmapy HTML."""
    heatmap_counts = parse_heatmap_data()
    if not heatmap_counts:
        return "<p><i>Brak danych do wygenerowania heatmapy – plik last30days_alerts.csv nie został znaleziony lub pusty.</i></p>"
    html = [
        f'<h2>🔥 Heatmapa wyzwolonych technik dla grupy <b>{apt_folder}</b></h2>',
        '<table class="matrix-table"><tr>'
    ]
    # TACTICS_ORDER == header
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        found = False
        for row in matrix.get(tactic, []):
            tid = row["Technique ID"]
            # Filtruj tylko techniki danej grupy APT, jeśli podano (dla Single sumuje globalnie!)
            if only_techniques is not None and tid not in only_techniques:
                continue
            cnt = heatmap_counts.get(tid, 0)
            color = heatmap_color_for_count(cnt) if cnt else DEFAULT_HEATMAP_COLOR
            html.append(
                f'<div class="matrix-technique" style="background:{color};border:1.5px solid #b6b6b6;">'
                f'<b>{tid}</b>'
                f'<div style="margin-top:5px;">'
                f'<span style="font-size:1.09em;'
                f'font-weight:600;'
                f'color:#d7263d;">{"🔥" if cnt else "–"}</span> '
                f'<span style="font-size:1.04em;">{cnt} alertów</span>'
                '</div></div>'
            )
            found = True
        if not found:
            html.append('<div class="matrix-technique" style="background:#ececec;">–</div>')
        html.append("</td>")
    html.append("</tr></table>")
    return "\n".join(html)

def generate_matrix_html(apt_folder, report_path, apt_mode=True):
    """Generuje index.html z matrycą, heatmapą, tabelką statusów."""
    status_path = os.path.join("mapping", apt_folder, "status.csv")
    if not os.path.exists(status_path):
        print(f"(!) Brak pliku {status_path}")
        return
    rows = list(csv.DictReader(open(status_path, encoding="utf-8")))
    # Uporządkuj do macierzy
    matrix = defaultdict(list)
    for r in rows:
        for t in r["Tactics"].split(","):
            key = t.strip().lower()
            if key in TACTICS_ORDER:
                matrix[key].append(r)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = [
        '<!DOCTYPE html>',
        '<html>',
        '<head>',
        '<meta charset="UTF-8">',
        f'<title>🛡️ Defender Lab Framework – macierz MITRE ATT&CK</title>',
        '<style>',
        # --- Styl z Twojego index.html demo! ---
        "body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7fafd; color: #23293b; margin: 0; padding: 0; }",
        ".container { max-width: 1400px; margin: 0 auto; padding: 30px; }",
        "h1 { color: #14247a; margin-top: 0; }",
        # ...tu cały CSS, jak miałeś (możesz skopiować z index.html demo)...
        ".matrix-table { width: 100%; border-collapse: collapse; background: #f5f8ff; font-size: 1.05em; }",
        ".matrix-table th, .matrix-table td { border: 1px solid #dde3ef; padding: 11px 7px; text-align: left; min-width: 140px; }",
        ".matrix-table th { background: #eaf0fa; color: #222b44; font-size: 1.09em; font-weight: 600; letter-spacing: 0.01em; position: sticky; top: 49px; z-index: 2; }",
        ".matrix-table td { background: #f9fbfd; vertical-align: top; min-width: 140px; }",
        ".matrix-technique { margin-bottom: 10px; padding: 10px 8px 10px 14px; border-radius: 7px; border: 1.2px solid #e5e9f2; background: #fff; box-shadow: 0 1.5px 7px #dde3ef33; position: relative; transition: box-shadow 0.13s; }",
        ".matrix-technique:hover { box-shadow: 0 2px 13px #8cc2ff33; border-color: #b3d3ff; }",
        ".matrix-technique b { font-size: 1.01em; color: #14247a; letter-spacing: 0.3px; }",
        ".badge { display: inline-block; padding: 3px 11px; border-radius: 6px; font-size: 0.93em; color: #fff; font-weight: 500; margin-right: 3px; margin-top: 2px; margin-bottom: 3px; }",
        ".badge-Tested { background: #40c057; }",
        ".badge-Audit { background: #ffd43b; color: #222; }",
        ".badge-Pending { background: #ff6b6b; }",
        "</style>",
        '</head>',
        '<body>',
        '<div class="container">',
        f'<h1>🛡️ Defender Lab Framework – macierz MITRE ATT&CK</h1>',
        f'<div style="margin:10px 0 18px 0; font-size:1.18em;">Matryca wygenerowana dla grupy: <b>{apt_folder}</b></div>',
        f'<p style="color:#557;">Wygenerowano: {now}</p>',
        '<table class="matrix-table"><tr>'
    ]
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        for row in matrix.get(tactic, []):
            status = row["Status"]
            bg = STATUS_BG_COLORS.get(status, "#fff")
            html.append(
                f'<div class="matrix-technique" style="background:{bg};">'
                f'<b>{row["Technique ID"]}</b><br>{row["Name"]}'
                f'<br><span class="badge badge-{status}">{status}</span>'
                '</div>'
            )
        html.append("</td>")
    html.append("</tr></table>")
    # ---- Dodaj heatmapę (tylko techniki danej grupy!) ----
    html.append(render_heatmap_section_for_matrix(
        matrix, apt_folder,
        only_techniques=[row["Technique ID"] for row in rows] if apt_mode else None
    ))
    # ---- Dodaj tabelę statusów (jak w index.html demo) ----
    html.append('<h2>📊 Tabela statusów</h2>')
    html.append('<table class="matrix-table"><tr>')
    html.append('<th>Technique ID</th><th>Name</th><th>Status</th><th>Linked Rule</th><th>Author</th></tr>')
    for row in rows:
        status = row["Status"]
        bg = STATUS_BG_COLORS.get(status, "#fff")
        html.append(
            f"<tr style='background:{bg};'>"
            f"<td>{row['Technique ID']}</td>"
            f"<td>{row['Name']}</td>"
            f"<td><span class='badge badge-{status}'>{status}</span></td>"
            f"<td>{row['Linked Rule']}</td>"
            f"<td>{row.get('Author','')}</td>"
            "</tr>"
        )
    html.append("</table>")
    html.append("</div></body></html>")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"[✓] Raport HTML wygenerowany do: {report_path}")

def main():
    print_banner()
    mode = choose_mode()
    techniques_db = load_enterprise_techniques()
    author = input("Podaj swoje imię lub alias: ").strip() or "Anon"
    if mode == 1:  # SingleTechnique
        apt_folder = "SingleTechnique"
        while True:
            tid = ask_for_technique(techniques_db)
            technique = techniques_db[tid]
            status = ask_status()
            alert_name = ask_alert_name()
            alert_md_path = generate_alert_md(tid, technique["name"], technique["tactics"], status, author, alert_name, apt_folder)
            alert_md_rel = os.path.relpath(alert_md_path, ".")
            generate_scenario_md_and_tags(tid, technique["name"], technique["tactics"], status, author, alert_md_rel, apt_folder)
            append_or_update_status_csv(apt_folder, {
                "Technique ID": tid,
                "Name": technique["name"],
                "Tactics": ", ".join(technique["tactics"]),
                "Status": status,
                "Linked Rule": alert_md_rel,
                "Author": author
            })
            more = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if more != "t":
                break
        # Warstwa do Navigatora + raport HTML
        techniques = list(csv.DictReader(open(os.path.join("mapping", apt_folder, "status.csv"), encoding="utf-8")))
        generate_layer_json(apt_folder, techniques)
        generate_matrix_html(apt_folder, os.path.join("report", apt_folder, "index.html"), apt_mode=False)

    elif mode == 2:  # APT Group
        all_folders = sorted([f for f in os.listdir("mapping") if os.path.isdir(os.path.join("mapping", f)) and f not in ("SingleTechnique",)])
        if all_folders:
            print("Dostępne foldery APT:", ", ".join(all_folders))
        apt_folder = input("Podaj nazwę grupy APT: ").strip()
        if not apt_folder:
            apt_folder = "APT"
        while True:
            tid = ask_for_technique(techniques_db)
            technique = techniques_db[tid]
            status = ask_status()
            alert_name = ask_alert_name()
            alert_md_path = generate_alert_md(tid, technique["name"], technique["tactics"], status, author, alert_name, apt_folder)
            alert_md_rel = os.path.relpath(alert_md_path, ".")
            generate_scenario_md_and_tags(tid, technique["name"], technique["tactics"], status, author, alert_md_rel, apt_folder)
            append_or_update_status_csv(apt_folder, {
                "Technique ID": tid,
                "Name": technique["name"],
                "Tactics": ", ".join(technique["tactics"]),
                "Status": status,
                "Linked Rule": alert_md_rel,
                "Author": author
            })
            more = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if more != "t":
                break
        # Warstwa do Navigatora + raport HTML
        techniques = list(csv.DictReader(open(os.path.join("mapping", apt_folder, "status.csv"), encoding="utf-8")))
        generate_layer_json(apt_folder, techniques)
        generate_matrix_html(apt_folder, os.path.join("report", apt_folder, "index.html"), apt_mode=True)

    elif mode == 3:  # Update
        print("--- Tryb UPDATE ---")
        print("Podaj nazwę grupy do update (lub SingleTechnique):")
        apt_folder = input("Nazwa: ").strip()
        if not apt_folder:
            apt_folder = "SingleTechnique"
        print("Aktualizuję raporty oraz warstwy...")
        techniques = list(csv.DictReader(open(os.path.join("mapping", apt_folder, "status.csv"), encoding="utf-8")))
        generate_layer_json(apt_folder, techniques)
        generate_matrix_html(apt_folder, os.path.join("report", apt_folder, "index.html"), apt_mode=(apt_folder!="SingleTechnique"))
        print("[✓] Update zakończony.")

if __name__ == "__main__":
    main()
