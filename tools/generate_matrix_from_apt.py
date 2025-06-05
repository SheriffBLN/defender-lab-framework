import os
import json
import csv
import re
import sys
from datetime import datetime
from tools.shared_utils import (
    STATUS_CSV_FIELDS, ensure_dir, generate_matrix_html, load_alert_counts, print_env_diagnostics
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
os.chdir(REPO_ROOT)

STIX_PATH = "tools/helpers/enterprise-attack.json"
CSV_PATH = "tools/enterprise_attack.csv"
DEFAULT_AUTHOR = "APT Matrix Generator"

def sanitize_filename(s):
    s = re.sub(r"[^\w\d\-_. ]", "", s)
    s = s.replace(" ", "_")
    return s[:50]

def load_techniques_csv():
    data = {}
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            data[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    return data

def list_all_groups_with_aliases(stix_path):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_list = []
    for obj in objs:
        if obj.get("type") == "intrusion-set":
            mitre_id = None
            aliases = []
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
            if obj.get("aliases"):
                aliases = obj.get("aliases")
            entry = {
                "name": obj.get("name"),
                "mitre_id": mitre_id,
                "aliases": aliases,
                "id": obj.get("id")
            }
            group_list.append(entry)
    return group_list

def print_groups_with_aliases(group_list):
    print("=== Grupy APT (ID | NAZWA | ALIASY) ===")
    for idx, g in enumerate(group_list):
        aliases = ", ".join(g.get("aliases", [])) if g.get("aliases") else "-"
        print(f"{idx+1:3}. {g['mitre_id'] or '---':6} | {g['name']:<24} | {aliases}")
    print("----------------------------------------")
    print(" 0  | Powrót do wyboru trybu / wyjście")

def pick_group(stix_path):
    while True:
        print("\nTryby wyboru:")
        print(" A – wybór grupy po ALIASIE (friendly name, lista)")
        print(" B – wybór grupy po nazwie lub ID (klasyczny)")
        print(" 0 – Wyjdź / zakończ")
        mode = input("Wybierz tryb (A/B/0): ").strip().upper()
        if mode == "0":
            return None
        if mode == "A":
            group_list = list_all_groups_with_aliases(stix_path)
            print_groups_with_aliases(group_list)
            inp = input("Podaj NAZWĘ lub ALIAS grupy (albo 0 by wrócić): ").strip().lower()
            if inp == "0":
                continue
            for g in group_list:
                all_names = [g["name"].lower()] + [a.lower() for a in g.get("aliases",[])]
                if inp in all_names or inp == (g["mitre_id"] or "").lower():
                    return g
            print("Nie znaleziono takiej grupy po aliasie.")
        elif mode == "B":
            group_list = list_all_groups_with_aliases(stix_path)
            inp = input("Podaj nazwę LUB ID grupy APT (albo 0 by wrócić): ").strip().lower()
            if inp == "0":
                continue
            for g in group_list:
                if inp == (g['name'] or '').lower() or inp == (g['mitre_id'] or '').lower():
                    return g
            print("Nie znaleziono takiej grupy po nazwie/ID.")
        else:
            print("Nieprawidłowy tryb, wybierz A/B/0.")

def extract_techniques_for_group(stix_path, group_entry):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_id = group_entry['id']
    uses = [r for r in objs if r.get("type") == "relationship" and r.get("source_ref") == group_id and r.get("relationship_type") == "uses"]
    techniques_ids = []
    for rel in uses:
        target = rel.get("target_ref")
        t_obj = next((o for o in objs if o.get("id") == target and o.get("type") == "attack-pattern"), None)
        if t_obj:
            ext_ref = next((r for r in t_obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext_ref and "external_id" in ext_ref:
                techniques_ids.append(ext_ref["external_id"].upper())
    return sorted(set(techniques_ids))

def get_technique_details_from_stix(tid):
    with open(STIX_PATH, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    for obj in objs:
        if obj.get("type") == "attack-pattern":
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
            if ext_id and ext_id.upper() == tid:
                description = obj.get("description", "").replace("\n", " ").replace("\r", "")
                parts = ext_id.split(".")
                if len(parts) == 2:
                    link = f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
                else:
                    link = f"https://attack.mitre.org/techniques/{ext_id}/"
                return description, link
    return "", ""

def extract_scenario_from_md(md_path):
    if not os.path.exists(md_path):
        return ""
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r"#SCENARIO\s*([\s\S]*?)#ENDSCENARIO", content, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""

def create_alert_file(group_folder, tid, tname, description, mitre_link):
    os.makedirs(group_folder, exist_ok=True)
    base_name = f"{tid}_{sanitize_filename(tname)}"
    alert_path_md = os.path.join(group_folder, f"{base_name}.md")
    alert_path_html = os.path.join(group_folder, f"{base_name}.html")
    scenario_block = "#SCENARIO\nTutaj wpisz swój opis scenariusza lub pozostaw do uzupełnienia.\n#ENDSCENARIO\n\n"
    if not os.path.exists(alert_path_md):
        with open(alert_path_md, "w", encoding="utf-8") as f:
            f.write(f"# Alert: {tname}\n\n")
            f.write(scenario_block)
            f.write(f"**Technique ID:** {tid}\n\n")
            f.write(f"**Description:** {description}\n\n")
            f.write(f"**MITRE Link:** {mitre_link}\n\n")
            f.write(f"Autor: {DEFAULT_AUTHOR}\n\n")
            f.write(f"<!--\nTactics: \nTechnique ID: {tid}\nStatus: Pending\n-->\n")
    else:
        with open(alert_path_md, "r", encoding="utf-8") as f:
            content = f.read()
        if "#SCENARIO" not in content:
            content = scenario_block + content
            with open(alert_path_md, "w", encoding="utf-8") as f:
                f.write(content)
    # Zawsze generujemy .html, aby scenario był aktualny!
    scenario_text = extract_scenario_from_md(alert_path_md)
    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {tname}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 700px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    .scenario-block {{ background: #f4f0d9; border-radius: 7px; padding: 1em 1.2em; margin-bottom: 1.2em; color:#4a4500; font-size:1.07em; border-left:5px solid #e1c553; }}
  </style>
</head>
<body>
<div class="card">
  <h1>Alert: {tname}</h1>
  <div class="meta"><b>Technique ID:</b> {tid}</div>
  <div class="scenario-block"><b>Opis scenariusza:</b><br>{scenario_text if scenario_text else "<i>Brak opisu scenariusza (#SCENARIO w .md)</i>"}</div>
  <div class="desc section"><b>Description:</b><br>{description}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{mitre_link}" target="_blank">{mitre_link}</a></div>
  <div class="author section"><b>Author:</b> {DEFAULT_AUTHOR}</div>
</div>
</body>
</html>
"""
    with open(alert_path_html, "w", encoding="utf-8") as f:
        f.write(html)

def update_change_history(old_history, user):
    history = []
    try:
        history = json.loads(old_history) if old_history else []
    except Exception:
        history = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    history = ([{"user": user, "time": now}] + history)[:5]
    return json.dumps(history, ensure_ascii=False)

def main(group_entry=None):
    print_env_diagnostics([
        "tools/helpers/enterprise-attack.json",
        "tools/enterprise_attack.csv",
        "tools/helpers/last30days_alerts.csv"
    ])
    print("=== Automatyczne generowanie macierzy ATT&CK dla grupy APT (ze STIX) ===")
    while True:
        if group_entry is None:
            group_entry = pick_group(STIX_PATH)
        if not group_entry:
            print("Przerywam generowanie.")
            return
        techniques_db = load_techniques_csv()
        try:
            techs = extract_techniques_for_group(STIX_PATH, group_entry)
        except Exception as e:
            print(f"Błąd: {e}")
            return
        print(f"Znaleziono {len(techs)} technik dla {group_entry['name']} ({group_entry['mitre_id']}): {', '.join(techs)}")
        apt_folder = group_entry['name'].replace(" ", "_")
        mapping_dir = os.path.join("mapping", apt_folder)
        alerts_dir = os.path.join("alerts", apt_folder)
        os.makedirs(mapping_dir, exist_ok=True)
        os.makedirs(alerts_dir, exist_ok=True)
        status_path = os.path.join(mapping_dir, "status.csv")
        alert_counts = load_alert_counts("tools/helpers/last30days_alerts.csv")
        status_rows = []
        for tid in techs:
            if tid not in techniques_db:
                print(f"(!) Brak opisu techniki {tid} w CSV – pomijam")
                continue
            t = techniques_db[tid]
            description, mitre_link = get_technique_details_from_stix(tid)
            base_name = f"{tid}_{sanitize_filename(t['name'])}"
            alert_filename_html = f"{base_name}.html"
            status_value = "Tested" if alert_counts.get(tid, 0) > 0 else "Pending"
            row = {
                "Technique ID": tid,
                "Name": t["name"],
                "Tactics": ", ".join(t["tactics"]),
                "Status": status_value,
                "Linked Rule": f"{os.path.join('alerts', apt_folder, alert_filename_html)}",
                "Author": DEFAULT_AUTHOR,
                "Description": description,
                "MITRE Link": mitre_link,
                "ChangeHistory": update_change_history("", DEFAULT_AUTHOR)
            }
            status_rows.append(row)
            create_alert_file(alerts_dir, tid, t["name"], description, mitre_link)
        with open(status_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=STATUS_CSV_FIELDS + ["ChangeHistory"])
            writer.writeheader()
            writer.writerows(status_rows)
        print(f"[✓] Plik status.csv gotowy w mapping/{apt_folder}/status.csv")
        print(f"[✓] Pliki alertów utworzone w alerts/{apt_folder}/")
        alias = input("Podaj alias (autor/generujący raport): ").strip() or DEFAULT_AUTHOR
        for row in status_rows:
            row["ChangeHistory"] = update_change_history(row.get("ChangeHistory", ""), alias)
        with open(status_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=STATUS_CSV_FIELDS + ["ChangeHistory"])
            writer.writeheader()
            writer.writerows(status_rows)
        report_dir = os.path.join("report", apt_folder)
        ensure_dir(report_dir)
        html_code = generate_matrix_html(
            status_rows,
            title=f"🛡️ Macierz MITRE ATT&CK — {apt_folder}",
            apt_folder=apt_folder,
            alert_counts=alert_counts
        )
        out_path = os.path.join(report_dir, "index.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_code)
        print(f"[✓] Raport HTML zapisany do: {out_path}")
        # Po generacji zapytaj czy chcesz jeszcze raz, czy zakończyć
        again = input("\nChcesz wygenerować macierz dla innej grupy? (T/N): ").strip().upper()
        if again != "T":
            break
        group_entry = None

if __name__ == "__main__":
    main()
