import os
import csv
import json
import re
import sys
from pathlib import Path
from tools.shared_utils import (
    STATUS_BG_COLORS, BADGE_COLORS, TACTICS_ORDER, STATUS_CSV_FIELDS,
    load_techniques_db, safe_filename, print_env_diagnostics,
    ensure_dir, generate_matrix_html, md_to_html_basic, load_alert_counts
)
from datetime import datetime

MITRE_TACTICS = {
    'reconnaissance': ('Reconnaissance', 'TA0043'),
    'resource-development': ('Resource Development', 'TA0042'),
    'initial-access': ('Initial Access', 'TA0001'),
    'execution': ('Execution', 'TA0002'),
    'persistence': ('Persistence', 'TA0003'),
    'privilege-escalation': ('Privilege Escalation', 'TA0004'),
    'defense-evasion': ('Defense Evasion', 'TA0005'),
    'credential-access': ('Credential Access', 'TA0006'),
    'discovery': ('Discovery', 'TA0007'),
    'lateral-movement': ('Lateral Movement', 'TA0008'),
    'collection': ('Collection', 'TA0009'),
    'command-and-control': ('Command and Control', 'TA0011'),
    'exfiltration': ('Exfiltration', 'TA0010'),
    'impact': ('Impact', 'TA0040'),
}

def print_banner():
    banner = r'''
    ╔═════════════════════════════════════════════════════╗
    ║           🛡️  Defender Lab Framework  🛡️            ║
    ╚═════════════════════════════════════════════════════╝
    '''
    print(banner)

def choose_mode():
    print("=== Wybierz tryb pracy ===")
    print("1) SingleTechnique (autonomiczny, sumuje techniki do własnej macierzy, NIE pobiera alertów globalnych)")
    print("2) APT Group (osobna matryca dla grupy – korzysta z alertów globalnych)")
    print("3) Update (masowa aktualizacja raportów na podstawie status.csv + auto MD→HTML)")
    while True:
        try:
            mode = int(input("Wybierz tryb (1/2/3): "))
            if mode in [1,2,3]:
                return mode
        except ValueError:
            pass
        print("Podaj poprawną wartość (1/2/3)")

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

def ask_alert_name(alert_folder):
    while True:
        alert_name = input("Podaj nazwę dla alertu (np. Suspicious_PS_Exec): ").strip()
        if not alert_name:
            alert_name = "alert"
        md_path = os.path.join(alert_folder, f"{alert_name}.md")
        if os.path.exists(md_path):
            choice = input(f"UWAGA: {alert_name}.md już istnieje w {alert_folder}! Czy chcesz nadpisać? (t/n): ").strip().lower()
            if choice == "t":
                return alert_name
            else:
                print("Podaj inną nazwę alertu.")
        else:
            return alert_name

def extract_scenario_desc(md_path):
    if not os.path.exists(md_path):
        return "(brak opisu scenariusza)"
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()
    scenario_match = re.search(r'#SCENARIO(.*?)#ENDSCENARIO', md_text, re.DOTALL | re.IGNORECASE)
    if scenario_match:
        desc = scenario_match.group(1).strip()
        return desc if desc else "(brak opisu scenariusza)"
    # fallback – stare podejście
    lines = []
    in_desc = False
    for line in md_text.splitlines():
        if "Opis scenariusza" in line:
            in_desc = True
            continue
        if in_desc:
            if line.strip() == "---" or line.startswith("**Technika:**"):
                break
            lines.append(line.strip())
    desc = "\n".join(lines).strip()
    return desc if desc else "(brak opisu scenariusza)"

def update_change_history(old_history, user):
    history = []
    try:
        history = json.loads(old_history) if old_history else []
    except Exception:
        history = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    history = ([{"user": user, "time": now}] + history)[:5]
    return json.dumps(history, ensure_ascii=False)

def format_change_history(hist_json):
    try:
        entries = json.loads(hist_json)
        return "<br>".join([f"{e['time']} | {e['user']}" for e in entries[:2]])
    except Exception:
        return "-"

def generate_alert_html(
    technique_id, technique_name, tactics, status, author, scenario_desc, mitre_desc, mitre_link, mitre_tactics=None
):
    def tactic_to_link(tactic):
        tac_key = tactic.lower().replace(" ", "-")
        label, ta_id = MITRE_TACTICS.get(tac_key, (tactic.title(), ""))
        if ta_id:
            url = f'https://attack.mitre.org/tactics/{ta_id}/'
            return f'<a href="{url}" target="_blank">{label} ({ta_id})</a>'
        return label
    tactics_clean = []
    if isinstance(mitre_tactics, (list, tuple)):
        tactics_clean = mitre_tactics
    elif isinstance(mitre_tactics, str):
        tactics_clean = [x.strip() for x in mitre_tactics.split(",") if x.strip()]
    elif isinstance(tactics, str):
        tactics_clean = [x.strip() for x in tactics.split(",") if x.strip()]
    else:
        tactics_clean = tactics or []
    tactics_links = " / ".join([tactic_to_link(t) for t in tactics_clean]) if tactics_clean else "-"
    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {technique_name}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 700px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author, .tactic, .status {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    .scenario-block {{ background: #f4f0d9; border-radius: 7px; padding: 1em 1.2em; margin-bottom: 1.2em; color:#4a4500; font-size:1.07em; border-left:5px solid #e1c553; }}
    pre {{ background: #eee; padding: .7em 1em; border-radius: 5px; }}
    code {{ background: #f6f6f6; padding: 2px 5px; border-radius: 2px; }}
    ul {{ margin-left: 1.6em; }}
  </style>
</head>
<body>
<div class="card">
  <h1>Alert: {technique_name}</h1>
  <div class="meta"><b>Technique ID:</b> {technique_id}</div>
  <div class="tactic section"><b>Tactics:</b> {tactics_links}</div>
  <div class="status section"><b>Status:</b> {status}</div>
  <div class="scenario-block"><b>Twój opis scenariusza:</b><br>{scenario_desc or "<i>(brak opisu scenariusza)</i>"}</div>
  <div class="desc section"><b>MITRE Description:</b><br>{mitre_desc or "<i>(brak)</i>"}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{mitre_link}" target="_blank">{mitre_link or ""}</a></div>
  <div class="author section"><b>Author:</b> {author}</div>
</div>
</body>
</html>
"""

def generate_alert_md_and_html(technique_id, technique_name, tactics, status, author, alert_name, apt_folder, techniques_db):
    content = f"""# Alert: {technique_name}

#SCENARIO
Tutaj wpisz opis scenariusza. Możesz używać wielu linii.
#ENDSCENARIO

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
    ensure_dir(alert_folder)
    md_path = os.path.join(alert_folder, f"{alert_name}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(content)
    info = techniques_db.get(technique_id, {})
    mitre_desc = info.get("description", "")
    mitre_link = info.get("mitre_link", "")
    mitre_tactics = info.get("tactics", tactics)
    scenario_desc = extract_scenario_desc(md_path)
    html_path = os.path.join(alert_folder, f"{alert_name}.html")
    html_code = generate_alert_html(
        technique_id, technique_name, tactics, status, author,
        scenario_desc, mitre_desc, mitre_link, mitre_tactics
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_code)
    return md_path

def generate_scenario_md_and_tags(technique_id, technique_name, tactics, status, author, alert_md_rel, apt_folder):
    scenario_folder = os.path.join("scenarios", apt_folder, technique_id)
    ensure_dir(scenario_folder)
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
    status_path = os.path.join("mapping", apt_folder, "status.csv")
    ensure_dir(os.path.dirname(status_path))
    all_rows = []
    if os.path.exists(status_path):
        with open(status_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["Technique ID"] == new_row["Technique ID"] and row["Linked Rule"] == new_row["Linked Rule"]:
                    continue
                all_rows.append(row)
    all_rows.append(new_row)
    fieldnames = STATUS_CSV_FIELDS + ["ChangeHistory"]
    with open(status_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

def extract_fields_from_md(md_text):
    import re
    meta = {}
    meta_block = re.search(r'<!--(.*?)-->', md_text, re.DOTALL)
    if meta_block:
        for line in meta_block.group(1).splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                meta[key.strip().lower()] = val.strip()
    def match(pattern):
        m = re.search(pattern, md_text)
        return m.group(1).strip() if m else ""
    tid = meta.get('technique id', match(r'\*\*Technika:\*\*\s*([^\n*]+)'))
    tname = meta.get('technique name', match(r'\*\*Nazwa:\*\*\s*([^\n*]+)'))
    tactics = meta.get('tactics', match(r'\*\*Taktyki:\*\*\s*([^\n*]+)'))
    status = meta.get('status', match(r'\*\*Status:\*\*\s*([^\n*]+)'))
    author = meta.get('author', match(r'\*\*Autor:\*\*\s*([^\n*]+)'))
    mitre_link = meta.get('mitre link', match(r'(https://attack\.mitre\.org/techniques/[^\s\)]+)'))
    scenario = ""
    scenario_match = re.search(r'#SCENARIO(.*?)#ENDSCENARIO', md_text, re.DOTALL | re.IGNORECASE)
    if scenario_match:
        scenario = scenario_match.group(1).strip()
    if not scenario:
        m = re.search(r'Alert:[^\n]*\n(.*?)(?:---|\Z)', md_text, re.DOTALL)
        if m:
            scenario = m.group(1).strip()
    return tid, tname, tactics, status, author, mitre_link, scenario

def refresh_md_to_html(alerts_folder, enterprise_csv="tools/enterprise_attack.csv"):
    print(f"Ładuję mapping technik z {enterprise_csv}...")
    techniques_db = load_techniques_db(enterprise_csv)
    count = 0
    for root, dirs, files in os.walk(alerts_folder):
        for filename in files:
            if filename.endswith(".md"):
                md_path = os.path.join(root, filename)
                html_path = md_path.replace(".md", ".html")
                with open(md_path, "r", encoding="utf-8") as f:
                    md_text = f.read()
                tid, tname, tactics, status, author, mitre_link, scenario = extract_fields_from_md(md_text)
                info = techniques_db.get(tid.strip().upper(), {})
                mitre_desc = info.get("description", "")
                if not tactics:
                    tactics = ", ".join(info.get("tactics", []))
                if not tname:
                    tname = info.get("name", "")
                if not mitre_link:
                    mitre_link = info.get("mitre_link", "")
                html_code = generate_alert_html(
                    tid, tname, tactics, status, author, scenario, mitre_desc, mitre_link, info.get("tactics", [])
                )
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_code)
                count += 1
    print(f"[✓] Wszystkie alerty .md przekonwertowane na zgodny HTML ({count} szt.).")

def main():
    print_env_diagnostics([
        "tools/enterprise_attack.csv",
        "tools/helpers/last30days_alerts.csv"
    ])
    print_banner()
    mode = choose_mode()
    techniques_db = load_techniques_db("tools/enterprise_attack.csv")

    if mode == 1 or mode == 2:
        author = input("Podaj imię lub alias autora: ").strip() or "Anon"
    if mode == 1:
        apt_folder = "SingleTechnique"
        alert_folder = os.path.join("alerts", apt_folder)
        while True:
            tid = ask_for_technique(techniques_db)
            technique = techniques_db[tid]
            status = ask_status()
            alert_name = ask_alert_name(alert_folder)
            alert_md_path = generate_alert_md_and_html(
                tid, technique["name"], technique["tactics"], status, author, alert_name, apt_folder, techniques_db
            )
            alert_md_rel = os.path.relpath(alert_md_path, ".")
            changehistory = update_change_history("", author)
            append_or_update_status_csv(apt_folder, {
                "Technique ID": tid,
                "Name": technique["name"],
                "Tactics": ", ".join(technique["tactics"]),
                "Status": status,
                "Linked Rule": alert_md_rel,
                "Liczba wykryć": "",
                "Author": author,
                "Description": technique.get("description", ""),
                "MITRE Link": technique.get("mitre_link", ""),
                "ChangeHistory": changehistory
            })
            generate_scenario_md_and_tags(tid, technique["name"], technique["tactics"], status, author, alert_md_rel, apt_folder)
            more = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if more != "t":
                break
        techniques = list(csv.DictReader(open(os.path.join("mapping", apt_folder, "status.csv"), encoding="utf-8")))
        alert_counts = load_alert_counts("tools/helpers/last30days_alerts.csv")
        def with_changehistory(row):
            row = dict(row)
            row["Historia zmian"] = format_change_history(row.get("ChangeHistory", ""))
            return row
        html = generate_matrix_html(
            [with_changehistory(r) for r in techniques],
            "🛡️ Macierz MITRE ATT&CK", 
            apt_folder, 
            alert_counts=alert_counts
        )
        ensure_dir(os.path.join("report", apt_folder))
        with open(os.path.join("report", apt_folder, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[✓] Raport HTML wygenerowany do: report/{apt_folder}/index.html")

    elif mode == 2:
        all_folders = sorted([f for f in os.listdir("mapping") if os.path.isdir(os.path.join("mapping", f)) and f not in ("SingleTechnique",)])
        if all_folders:
            print("Dostępne foldery APT:", ", ".join(all_folders))
        apt_folder = input("Podaj nazwę grupy APT: ").strip()
        if not apt_folder:
            apt_folder = "APT"
        alert_folder = os.path.join("alerts", apt_folder)
        while True:
            tid = ask_for_technique(techniques_db)
            technique = techniques_db[tid]
            status = ask_status()
            alert_name = ask_alert_name(alert_folder)
            alert_md_path = generate_alert_md_and_html(
                tid, technique["name"], technique["tactics"], status, author, alert_name, apt_folder, techniques_db
            )
            alert_md_rel = os.path.relpath(alert_md_path, ".")
            changehistory = update_change_history("", author)
            append_or_update_status_csv(apt_folder, {
                "Technique ID": tid,
                "Name": technique["name"],
                "Tactics": ", ".join(technique["tactics"]),
                "Status": status,
                "Linked Rule": alert_md_rel,
                "Liczba wykryć": "",
                "Author": author,
                "Description": technique.get("description", ""),
                "MITRE Link": technique.get("mitre_link", ""),
                "ChangeHistory": changehistory
            })
            generate_scenario_md_and_tags(tid, technique["name"], technique["tactics"], status, author, alert_md_rel, apt_folder)
            more = input("Dodać kolejną technikę? (t/n): ").strip().lower()
            if more != "t":
                break
        techniques = list(csv.DictReader(open(os.path.join("mapping", apt_folder, "status.csv"), encoding="utf-8")))
        alert_counts = load_alert_counts("tools/helpers/last30days_alerts.csv")
        def with_changehistory(row):
            row = dict(row)
            row["Historia zmian"] = format_change_history(row.get("ChangeHistory", ""))
            return row
        html = generate_matrix_html(
            [with_changehistory(r) for r in techniques],
            "🛡️ Macierz MITRE ATT&CK", apt_folder, alert_counts=alert_counts
        )
        ensure_dir(os.path.join("report", apt_folder))
        with open(os.path.join("report", apt_folder, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[✓] Raport HTML wygenerowany do: report/{apt_folder}/index.html")

    elif mode == 3:
        update_user = input("Podaj alias osoby wykonującej masowy update (np. UpdateBot): ").strip() or "UpdateBot"
        print("--- Tryb UPDATE ---")
        print("Wyszukiwanie wszystkich plików status.csv w mapping/ ...")
        mapping_dir = "mapping"
        status_files = []
        for root, dirs, files in os.walk(mapping_dir):
            for file in files:
                if file == "status.csv":
                    apt_folder = os.path.relpath(root, mapping_dir)
                    status_files.append((apt_folder, os.path.join(root, file)))
        if not status_files:
            print("(!) Nie znaleziono żadnych plików status.csv w mapping/")
            return
        print(f"Znaleziono {len(status_files)} plików status.csv. Aktualizuję wszystkie raporty i warstwy ...\n")
        for apt_folder, status_path in status_files:
            updated_rows = []
            with open(status_path, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row["ChangeHistory"] = update_change_history(row.get("ChangeHistory", ""), update_user)
                    updated_rows.append(row)
            with open(status_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=STATUS_CSV_FIELDS + ["ChangeHistory"])
                writer.writeheader()
                writer.writerows(updated_rows)
            folder_name = apt_folder if apt_folder != '.' else ''
            try:
                print(f"⏳ Aktualizuję: mapping/{folder_name}/status.csv")
                techniques = updated_rows
                alert_counts = load_alert_counts("tools/helpers/last30days_alerts.csv")
                def with_changehistory(row):
                    row = dict(row)
                    row["Historia zmian"] = format_change_history(row.get("ChangeHistory", ""))
                    return row
                html = generate_matrix_html(
                    [with_changehistory(r) for r in techniques],
                    "🛡️ Macierz MITRE ATT&CK", folder_name, alert_counts=alert_counts
                )
                ensure_dir(os.path.join("report", folder_name))
                with open(os.path.join("report", folder_name, "index.html"), "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[✓] Raport HTML wygenerowany do: report/{folder_name}/index.html")
            except Exception as e:
                print(f"(!) Błąd przy aktualizacji {status_path}: {e}")

        print("\n[✓] Wszystkie raporty index.html zaktualizowane.")
        print("[INFO] Odświeżam automatycznie wszystkie alerty .md → .html...")
        refresh_md_to_html("alerts")
        print("[✓] Automatyczne odświeżenie HTML alertów z .md zakończone.\n")

if __name__ == "__main__":
    main()
