import os
import json
import csv
import re

STIX_PATH = "tools/helpers/enterprise-attack.json"
CSV_PATH = "tools/enterprise_attack.csv"
DEFAULT_AUTHOR = "APT Matrix Generator"

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

def sanitize_filename(s):
    # Usuwa znaki niedozwolone w nazwach plików
    s = re.sub(r"[^\w\d\-_. ]", "", s)
    s = s.replace(" ", "_")
    return s[:50]  # max długość (opcjonalnie)

def list_all_groups(stix_path):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_list = []
    for obj in objs:
        if obj.get("type") == "intrusion-set":
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
            entry = {
                "name": obj.get("name"),
                "mitre_id": mitre_id,
                "id": obj.get("id")
            }
            group_list.append(entry)
    return group_list

def list_all_groups_with_aliases(stix_path):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_list = []
    for obj in objs:
        if obj.get("type") == "intrusion-set":
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
            entry = {
                "name": obj.get("name"),
                "mitre_id": mitre_id,
                "id": obj.get("id"),
                "aliases": obj.get("aliases", [])
            }
            group_list.append(entry)
    return group_list

def show_group_aliases(stix_path):
    group_list = list_all_groups_with_aliases(stix_path)
    print("=== Wybierz numer grupy, aby zobaczyć aliasy ===")
    for idx, g in enumerate(group_list):
        print(f"{idx+1:3}. {g['mitre_id'] or '---':6} | {g['name']}")
    print("-----------------------------------------------")
    wybor = input("Podaj **numer z listy** (np. 181): ").strip()
    try:
        idx = int(wybor) - 1
        if 0 <= idx < len(group_list):
            aliases = group_list[idx]["aliases"]
            if aliases:
                print(f"Aliasów dla {group_list[idx]['name']} ({group_list[idx]['mitre_id']}): {', '.join(aliases)}")
            else:
                print("Brak aliasów dla tej grupy.")
        else:
            print("Błąd: Podaj poprawny numer grupy z listy.")
    except Exception:
        print("Błąd: Podaj poprawny **numer** grupy z listy.")

def pick_group(stix_path):
    group_list = list_all_groups(stix_path)
    if not group_list:
        print("[Błąd] Brak poprawnych danych STIX lub nie znaleziono żadnej grupy APT.")
        return None
    print("=== Lista dostępnych grup (ID | nazwa) ===")
    for idx, g in enumerate(group_list):
        print(f"{idx+1:3}. {g['mitre_id'] or '---':6} | {g['name']}")
    print("------------------------------------------")
    inp = input("Podaj nazwę LUB ID grupy APT: ").strip().lower()
    for g in group_list:
        if inp == (g['name'] or '').lower() or inp == (g['mitre_id'] or '').lower():
            return g
    print(f"Nie znaleziono grupy: {inp}")
    return None

def pick_group_with_alias_option(stix_path):
    group_list = list_all_groups_with_aliases(stix_path)
    if not group_list:
        print("[Błąd] Brak poprawnych danych STIX lub nie znaleziono żadnej grupy APT.")
        return None
    while True:
        print("=== Lista dostępnych grup (ID | nazwa) ===")
        for idx, g in enumerate(group_list):
            print(f"{idx+1:3}. {g['mitre_id'] or '---':6} | {g['name']}")
        print("[A] Pokaż aliasy dla wybranej grupy")
        print("------------------------------------------")
        inp = input("Podaj nazwę LUB ID grupy APT albo [A] by wyświetlić aliasy: ").strip().lower()
        if inp == "a":
            show_group_aliases(stix_path)
            input("\nWciśnij Enter aby wrócić do wyboru grupy...\n")
            continue
        for g in group_list:
            if inp == (g['name'] or '').lower() or inp == (g['mitre_id'] or '').lower():
                return g
        print(f"Nie znaleziono grupy: {inp}")

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

def create_alert_file(group_folder, tid, tname, description, mitre_link):
    os.makedirs(group_folder, exist_ok=True)
    base_name = f"{tid}_{sanitize_filename(tname)}"
    alert_path_md = os.path.join(group_folder, f"{base_name}.md")
    alert_path_html = os.path.join(group_folder, f"{base_name}.html")

    # Generuj .md (nie nadpisuj jeśli istnieje)
    if not os.path.exists(alert_path_md):
        with open(alert_path_md, "w", encoding="utf-8") as f:
            f.write(f"# Alert: {tname}\n\n")
            f.write(f"**Technique ID:** {tid}\n\n")
            f.write(f"**Description:** {description}\n\n")
            f.write(f"**MITRE Link:** {mitre_link}\n\n")
            f.write(f"Autor: {DEFAULT_AUTHOR}\n\n")
            f.write(f"<!--\nTactics: \nTechnique ID: {tid}\nStatus: Pending\n-->\n")

    # Generuj .html (nie nadpisuj jeśli istnieje)
    if not os.path.exists(alert_path_html):
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
  </style>
</head>
<body>
<div class="card">
  <h1>Alert: {tname}</h1>
  <div class="meta"><b>Technique ID:</b> {tid}</div>
  <div class="desc section"><b>Description:</b><br>{description}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{mitre_link}" target="_blank">{mitre_link}</a></div>
  <div class="author section"><b>Author:</b> {DEFAULT_AUTHOR}</div>
</div>
</body>
</html>
"""
        with open(alert_path_html, "w", encoding="utf-8") as f:
            f.write(html)

def main(group_entry=None):
    print("=== Automatyczne generowanie macierzy ATT&CK dla grupy APT (bez stix2) ===")
    if group_entry is None:
        group_entry = pick_group(STIX_PATH)
    if not group_entry:
        print("Anulowano wybór.")
        return
    techniques_db = load_techniques_csv()
    try:
        techs = extract_techniques_for_group(STIX_PATH, group_entry)
    except Exception as e:
        print(f"Błąd: {e}")
        return
    print(f"Znaleziono {len(techs)} technik dla {group_entry['name']} ({group_entry['mitre_id']}): {', '.join(techs)}")
    apt_folder = group_entry['name'].replace(" ", "_")
    os.makedirs(os.path.join("mapping", apt_folder), exist_ok=True)
    os.makedirs(os.path.join("alerts", apt_folder), exist_ok=True)
    status_path = os.path.join("mapping", apt_folder, "status.csv")
    with open(status_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Technique ID","Name","Tactics","Status","Linked Rule","Author","Description","MITRE Link"
        ])
        writer.writeheader()
        for tid in techs:
            if tid not in techniques_db:
                print(f"(!) Brak opisu techniki {tid} w CSV – pomijam")
                continue
            t = techniques_db[tid]
            description, mitre_link = get_technique_details_from_stix(tid)
            base_name = f"{tid}_{sanitize_filename(t['name'])}"
            alert_filename_html = f"{base_name}.html"
            alert_relpath_html = f"../../alerts/{apt_folder}/{alert_filename_html}"
            writer.writerow({
                "Technique ID": tid,
                "Name": t["name"],
                "Tactics": ", ".join(t["tactics"]),
                "Status": "Pending",
                "Linked Rule": f'<a href="{alert_relpath_html}" target="_blank">{tid} ({t["name"]})</a>',
                "Author": DEFAULT_AUTHOR,
                "Description": description,
                "MITRE Link": mitre_link
            })
            # Twórz alerty .md i .html
            create_alert_file(
                os.path.join("alerts", apt_folder),
                tid, t["name"], description, mitre_link
            )
    print(f"[✓] Plik status.csv gotowy w mapping/{apt_folder}/status.csv")
    print(f"[✓] Pliki alertów utworzone w alerts/{apt_folder}/")
    print("Możesz teraz odpalić tryb 3 (Update) w defender_lab.py, żeby wygenerować macierz i warstwę Navigatora!")

if __name__ == "__main__":
    main()
